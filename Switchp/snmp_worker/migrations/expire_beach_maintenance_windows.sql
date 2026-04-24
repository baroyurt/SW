-- Migration: SW38-BEACH ve SW39-BEACH için aktif bakım pencerelerini kapat
-- SW39-BEACH ve SW38-BEACH cihazlarına ait geçici alarm kapatma kayıtları
-- (maintenance_windows) kaldırılır; alarmlar yeniden aktif hale gelir.
-- Idempotent — defalarca çalıştırılabilir.
-- Tarih: 2026-04-25
--
-- NOT: Bu script önce eksik kolonları ekler (tablo eski şema ile oluşturulmuş olabilir),
--      ardından BEACH cihazlarına ait bakım pencerelerini kapatır.

-- ============================================================
-- 1. Eksik kolonları ekle (idempotent)
-- ============================================================
IF OBJECT_ID('dbo.maintenance_windows','U') IS NOT NULL
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('maintenance_windows') AND name = 'device_name')
        ALTER TABLE maintenance_windows ADD device_name VARCHAR(100) DEFAULT NULL;

    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('maintenance_windows') AND name = 'recurring')
        ALTER TABLE maintenance_windows ADD recurring BIT DEFAULT 0;

    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('maintenance_windows') AND name = 'recur_days')
        ALTER TABLE maintenance_windows ADD recur_days VARCHAR(20) DEFAULT NULL;

    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('maintenance_windows') AND name = 'recur_start')
        ALTER TABLE maintenance_windows ADD recur_start TIME DEFAULT NULL;

    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('maintenance_windows') AND name = 'recur_end')
        ALTER TABLE maintenance_windows ADD recur_end TIME DEFAULT NULL;

    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('maintenance_windows') AND name = 'suppress_alarms')
        ALTER TABLE maintenance_windows ADD suppress_alarms BIT DEFAULT 1;

    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('maintenance_windows') AND name = 'created_by')
        ALTER TABLE maintenance_windows ADD created_by VARCHAR(100) DEFAULT NULL;

    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('maintenance_windows') AND name = 'device_id')
        ALTER TABLE maintenance_windows ADD device_id INT DEFAULT NULL;
END
GO

-- ============================================================
-- 2. BEACH bakım pencerelerini kapat / sil
-- ============================================================
IF OBJECT_ID('dbo.maintenance_windows','U') IS NOT NULL
BEGIN
    -- Aktif tek seferlik (non-recurring) pencereleri sonlandır
    UPDATE maintenance_windows
    SET end_time = GETDATE()
    WHERE suppress_alarms = 1
      AND recurring = 0
      AND end_time > GETDATE()
      AND device_name IN ('SW38-BEACH', 'SW39-BEACH');

    -- Tekrarlayan pencereleri kaldır
    DELETE FROM maintenance_windows
    WHERE suppress_alarms = 1
      AND recurring = 1
      AND device_name IN ('SW38-BEACH', 'SW39-BEACH');

    -- device_id ile eşleşenleri de kapat (device_name yerine ID kullanılmış olabilir)
    IF OBJECT_ID('dbo.snmp_devices','U') IS NOT NULL
    BEGIN
        UPDATE maintenance_windows
        SET end_time = GETDATE()
        WHERE suppress_alarms = 1
          AND recurring = 0
          AND end_time > GETDATE()
          AND device_id IN (
              SELECT id FROM snmp_devices
              WHERE name IN ('SW38-BEACH', 'SW39-BEACH')
          );

        DELETE FROM maintenance_windows
        WHERE suppress_alarms = 1
          AND recurring = 1
          AND device_id IN (
              SELECT id FROM snmp_devices
              WHERE name IN ('SW38-BEACH', 'SW39-BEACH')
          );
    END
END
GO

SELECT 'SUCCESS: SW38-BEACH ve SW39-BEACH bakım pencereleri kapatildi, alarmlar aktif.' AS status;
