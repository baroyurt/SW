-- ============================================================================
-- MERGED: Alarm Tablosu Düzeltmeleri ve Yapılandırması
-- Birleştirilen dosyalar:
--   - fix_alarms_status_enum_uppercase.sql    (status sütununu büyük harfe çevir)
--   - fix_acknowledgment_type_constraint.sql  (CHK constraint genişletme)
--   - add_alarms_is_silenced_computed.sql     (is_silenced hesaplanmış sütun)
--   - add_core_link_down_alarm.sql            (alarm_severity_config: core_link_down)
--   - enable_description_change_notifications.sql (alarm_severity_config: description_changed)
-- Tümü idempotent — defalarca çalıştırılabilir.
-- ============================================================================

-- ── 1. status sütunu değerlerini büyük harfe çevir ──────────────────────────

UPDATE alarms
SET status = CASE
    WHEN status = 'active'       THEN 'ACTIVE'
    WHEN status = 'acknowledged' THEN 'ACKNOWLEDGED'
    WHEN status = 'resolved'     THEN 'RESOLVED'
    ELSE UPPER(status)
END
WHERE status IN ('active', 'acknowledged', 'resolved');
GO

ALTER TABLE alarms ALTER COLUMN status VARCHAR(50) NOT NULL;
GO

-- ── 2. acknowledgment_type CHECK kısıtını genişlet ──────────────────────────

IF EXISTS (
    SELECT 1 FROM sys.check_constraints
    WHERE  name = 'CHK_alarms_acknowledgment_type'
      AND  parent_object_id = OBJECT_ID('dbo.alarms')
)
BEGIN
    ALTER TABLE [dbo].[alarms] DROP CONSTRAINT [CHK_alarms_acknowledgment_type];
END
GO

ALTER TABLE [dbo].[alarms]
    ADD CONSTRAINT [CHK_alarms_acknowledgment_type]
        CHECK ([acknowledgment_type] IN (
            'known_change', 'silenced', 'resolved',
            'false_alarm', 'mac_moved', 'device_registered', ''
        ));
GO

-- ── 3. is_silenced hesaplanmış sütun ────────────────────────────────────────

IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_NAME = 'alarms' AND COLUMN_NAME = 'is_silenced'
)
    ALTER TABLE dbo.alarms
        ADD is_silenced AS (
            CAST(
                CASE WHEN silence_until IS NOT NULL AND silence_until > GETDATE()
                     THEN 1 ELSE 0
                END
            AS BIT)
        );
GO

-- ── 4. alarm_severity_config: core_link_down ────────────────────────────────

UPDATE alarm_severity_config
SET severity = 'CRITICAL', telegram_enabled = 1, email_enabled = 1,
    description = 'Core uplink bağlantısı kesildi'
WHERE alarm_type = 'core_link_down';

IF @@ROWCOUNT = 0
    INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description)
    VALUES ('core_link_down', 'CRITICAL', 1, 1, 'Core uplink bağlantısı kesildi');
GO

-- ── 5. alarm_severity_config: description_changed bildirimlerini etkinleştir ─

UPDATE alarm_severity_config
SET telegram_enabled = 1, email_enabled = 1, severity = 'MEDIUM'
WHERE alarm_type = 'description_changed';
GO

SELECT 'SUCCESS: merged_alarm_fixes migration complete' AS status;
