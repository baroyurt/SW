-- ============================================================================
-- Migration: optimize_port_snapshot
-- Date: 2026-03-16
-- Purpose: Convert port_snapshot from an append-only history table to a
--          single-row-per-port "current state" table.
--
-- Background
-- ----------
-- The Python SNMP worker previously INSERT-ed a new port_snapshot row on
-- EVERY poll cycle (every 30 s by default).  With hundreds of ports this
-- results in millions of rows per day (observed: 2.4 GiB / 16.8 M rows).
--
-- Only the MOST RECENT row per (device_id, port_number) is ever read by the
-- change-detection logic.  Historical snapshots are redundant because actual
-- changes are logged in port_change_history.
--
-- Fix
-- ---
-- 1. Delete all duplicate rows -- keep only the latest row per port.
-- 2. Add UNIQUE CONSTRAINT uq_ps_device_port (device_id, port_number) so that the
--    worker can use MERGE (UPSERT) going forward.
-- 3. Drop the old composite index idx_device_port_time / idx_ps_device_port_time
--    (superseded by the unique constraint).
--
-- Safe to run multiple times (idempotent via IF EXISTS guards).
-- ============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Step 1: Remove duplicate rows, keeping only the latest per device+port.
-- ─────────────────────────────────────────────────────────────────────────────
WITH cte AS (
    SELECT id,
           ROW_NUMBER() OVER (PARTITION BY device_id, port_number ORDER BY id DESC) AS rn
    FROM port_snapshot
)
DELETE FROM cte WHERE rn > 1;

-- ─────────────────────────────────────────────────────────────────────────────
-- Step 2: Trim any remaining rows older than 15 days.
--         (After step 1 this is at most one orphan row per port for devices
--          that have been decommissioned.)
-- ─────────────────────────────────────────────────────────────────────────────
DELETE FROM port_snapshot
WHERE snapshot_timestamp < DATEADD(DAY, -15, GETDATE());

-- ─────────────────────────────────────────────────────────────────────────────
-- Step 3: Add the unique constraint that enables UPSERT.
--         Guarded so re-running the migration is safe.
-- ─────────────────────────────────────────────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='uq_ps_device_port' AND object_id=OBJECT_ID('port_snapshot'))
BEGIN
    ALTER TABLE port_snapshot ADD CONSTRAINT uq_ps_device_port UNIQUE (device_id, port_number);
END

-- ─────────────────────────────────────────────────────────────────────────────
-- Step 4: Drop the old idx_device_port_time / idx_ps_device_port_time index
--         (superseded by the unique constraint above).
-- ─────────────────────────────────────────────────────────────────────────────
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_device_port_time' AND object_id=OBJECT_ID('port_snapshot'))
    DROP INDEX idx_device_port_time ON port_snapshot;

IF EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_ps_device_port_time' AND object_id=OBJECT_ID('port_snapshot'))
    DROP INDEX idx_ps_device_port_time ON port_snapshot;

SELECT 'optimize_port_snapshot migration complete' AS status;
