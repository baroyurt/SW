-- Migration: add_polling_data_retention
-- Date: 2026-03-18
-- Purpose: Prevent unbounded growth of device_polling_data.
--
-- Background
-- ----------
-- The Python SNMP worker inserts one row per device per poll cycle
-- (every ~30 seconds).  With 38 devices that produces ~109,440 rows/day.
-- With no cleanup the table currently holds 419 000+ rows (7 weeks of data)
-- and will grow to millions within months, consuming gigabytes of disk.
--
-- Only recent polling data is valuable for dashboards and trend graphs.
-- Alarms and port changes are stored in dedicated tables, so losing old
-- device_polling_data rows does not affect any alarm or audit history.
--
-- Fix
-- ---
-- 1. Purge rows older than 7 days immediately (one-off cleanup).
-- 2. Schedule recurring cleanup via SQL Server Agent (see note below).
--
-- Safe to run multiple times (idempotent).

-- ─────────────────────────────────────────────────────────────────────────────
-- Step 1: One-off purge of rows older than 7 days.
-- ─────────────────────────────────────────────────────────────────────────────
DELETE FROM device_polling_data
WHERE poll_timestamp < DATEADD(DAY, -7, GETDATE());

-- ─────────────────────────────────────────────────────────────────────────────
-- Step 2: Scheduled cleanup via SQL Server Agent.
-- NOTE: MySQL EVENT is not supported in SQL Server.
-- Create a SQL Server Agent Job to run the following DELETE daily:
--   DELETE FROM device_polling_data WHERE poll_timestamp < DATEADD(DAY, -7, GETDATE());
-- ─────────────────────────────────────────────────────────────────────────────

SELECT 'add_polling_data_retention migration complete' AS status;
