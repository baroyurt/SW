-- ============================================================================
-- Migration: Fix alarms table status enum to use uppercase values
-- Date: 2026-02-14
-- Description: Updates alarms status enum from lowercase to uppercase
--              to match AlarmStatus enum in Python code and fix errors like:
--              "'active' is not among the defined enum values. 
--               Enum name: alarmstatus. 
--               Possible values: ACTIVE, ACKNOWLEDGE.., RESOLVED"
-- ============================================================================

-- Use the correct database
USE switchdb;

-- Step 1: Update existing alarm data to uppercase
-- This converts any existing lowercase values to uppercase before changing enum
UPDATE alarms 
SET status = CASE 
    WHEN status = 'active' THEN 'ACTIVE'
    WHEN status = 'acknowledged' THEN 'ACKNOWLEDGED'
    WHEN status = 'resolved' THEN 'RESOLVED'
    ELSE UPPER(status)
END
WHERE status IN ('active', 'acknowledged', 'resolved');

-- Step 2: Alter the enum column definition in alarms table
-- This changes the enum to accept only uppercase values
ALTER TABLE alarms 
MODIFY COLUMN status 
enum('ACTIVE','ACKNOWLEDGED','RESOLVED') 
DEFAULT 'ACTIVE';

-- Step 3: Verify the change
DESCRIBE alarms;

-- Step 4: Check current alarm data
SELECT id, device_id, alarm_type, status, severity, port_number, title 
FROM alarms 
ORDER BY id DESC 
LIMIT 10;

-- ============================================================================
-- Expected output for DESCRIBE alarms:
-- Field: status
-- Type: enum('ACTIVE','ACKNOWLEDGED','RESOLVED')
-- Default: ACTIVE
-- ============================================================================
