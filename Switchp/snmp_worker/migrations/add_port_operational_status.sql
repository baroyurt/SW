-- ============================================================================
-- Add Port Operational Status Tracking
-- Date: 2026-02-16
-- Purpose: Preserve port connection info when port goes down
-- ============================================================================
--
-- Issue: When a port goes down, connection data is being cleared
-- Solution: Add operational status tracking separate from connection data
--
-- This allows:
-- 1. Port to show as "down" (red) while preserving connection info
-- 2. When port comes back up, compare with preserved data
-- 3. If data matches → no alarm
-- 4. If data changed → create alarm
-- ============================================================================

USE switchdb;

-- Add operational status column to ports table if it doesn't exist
SET @column_exists = (
    SELECT COUNT(*) 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = 'switchdb' 
    AND TABLE_NAME = 'ports' 
    AND COLUMN_NAME = 'oper_status'
);

SET @sql = IF(@column_exists = 0,
    'ALTER TABLE ports ADD COLUMN oper_status VARCHAR(20) DEFAULT ''unknown'' COMMENT ''Operational status from SNMP (up/down)''',
    'SELECT ''Column oper_status already exists'' AS status'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add last status update timestamp
SET @column_exists = (
    SELECT COUNT(*) 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = 'switchdb' 
    AND TABLE_NAME = 'ports' 
    AND COLUMN_NAME = 'last_status_update'
);

SET @sql = IF(@column_exists = 0,
    'ALTER TABLE ports ADD COLUMN last_status_update DATETIME DEFAULT NULL COMMENT ''Last time operational status was updated''',
    'SELECT ''Column last_status_update already exists'' AS status'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Verify columns were added
SELECT 'SUCCESS: Port operational status columns added' AS status;

SELECT 
    COLUMN_NAME,
    COLUMN_TYPE,
    IS_NULLABLE,
    COLUMN_DEFAULT,
    COLUMN_COMMENT
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'switchdb'
AND TABLE_NAME = 'ports'
AND COLUMN_NAME IN ('oper_status', 'last_status_update')
ORDER BY COLUMN_NAME;
