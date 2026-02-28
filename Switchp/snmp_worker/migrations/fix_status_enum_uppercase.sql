-- ============================================================================
-- Migration: Fix status enum to use uppercase values
-- Date: 2026-02-13
-- Description: Updates snmp_devices status enum from lowercase to uppercase
--              to match DeviceStatus enum in Python code and fix errors like:
--              "Database error: 'online' is not among the defined enum values"
-- ============================================================================

-- Use the correct database
USE switchdb;

-- Step 1: Update existing data to uppercase
-- This converts any existing lowercase values to uppercase before changing enum
UPDATE snmp_devices 
SET status = CASE 
    WHEN status = 'online' THEN 'ONLINE'
    WHEN status = 'offline' THEN 'OFFLINE'
    WHEN status = 'error' THEN 'ERROR'
    ELSE status
END
WHERE status IN ('online', 'offline', 'error');

-- Step 2: Alter the enum column definition
-- This changes the enum to accept only uppercase values
ALTER TABLE snmp_devices 
MODIFY COLUMN status 
enum('ONLINE','OFFLINE','UNREACHABLE','ERROR') 
DEFAULT 'OFFLINE';

-- Step 3: Verify the change
DESCRIBE snmp_devices;

-- Step 4: Check current data
SELECT id, name, ip_address, status FROM snmp_devices;

-- ============================================================================
-- Expected output for DESCRIBE snmp_devices:
-- Field: status
-- Type: enum('ONLINE','OFFLINE','UNREACHABLE','ERROR')
-- Default: OFFLINE
-- ============================================================================
