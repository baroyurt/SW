-- Quick Fix: Enable description_changed alarm notifications
-- This allows existing SNMP-detected description changes to generate notifications
-- Manual web UI changes still need separate solution (see PORT_DESCRIPTION_ALARM_SORUNU.md)

UPDATE alarm_severity_config 
SET 
    telegram_enabled = TRUE, 
    email_enabled = TRUE,
    severity = 'MEDIUM'
WHERE alarm_type = 'description_changed';

-- Verify the update
SELECT alarm_type, severity, telegram_enabled, email_enabled, description 
FROM alarm_severity_config 
WHERE alarm_type = 'description_changed';
