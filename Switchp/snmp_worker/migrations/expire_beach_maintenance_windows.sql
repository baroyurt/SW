-- Migration: SW38-BEACH ve SW39-BEACH için aktif bakım pencerelerini kapat
-- SW39-BEACH ve SW38-BEACH cihazlarına ait geçici alarm kapatma kayıtları
-- (maintenance_windows) kaldırılır; alarmlar yeniden aktif hale gelir.
-- Idempotent — defalarca çalıştırılabilir.
-- Tarih: 2026-04-25

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
GO

SELECT 'SUCCESS: SW38-BEACH ve SW39-BEACH bakım pencereleri kapatildi, alarmlar aktif.' AS status;
