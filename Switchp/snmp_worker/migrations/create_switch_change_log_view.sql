-- Create view for per-switch change logging
-- This makes it easy to query historical changes per switch

IF OBJECT_ID('dbo.switch_change_log','V') IS NOT NULL DROP VIEW switch_change_log;
GO
CREATE VIEW switch_change_log AS
SELECT TOP (2147483647)
    pch.id,
    pch.device_id,
    d.name        AS switch_name,
    d.ip_address  AS switch_ip,
    pch.port_number,
    pch.change_type,
    pch.old_value,
    pch.new_value,
    pch.detected_at,
    pch.alarm_created,
    pch.alarm_id,
    a.severity    AS alarm_severity,
    a.status      AS alarm_status
FROM port_change_history pch
JOIN snmp_devices d ON pch.device_id = d.id
LEFT JOIN alarms a ON pch.alarm_id = a.id
ORDER BY pch.detected_at DESC;
GO

-- Example queries:

-- Get all changes for a specific switch:
-- SELECT * FROM switch_change_log WHERE switch_name = 'SW35-BALO' ORDER BY detected_at DESC;

-- Get recent changes for all switches:
-- SELECT * FROM switch_change_log WHERE detected_at > DATEADD(HOUR, -24, GETDATE());

-- Get changes by type:
-- SELECT * FROM switch_change_log WHERE change_type = 'description_changed' ORDER BY detected_at DESC;

-- Get changes that created alarms:
-- SELECT * FROM switch_change_log WHERE alarm_created = 1 ORDER BY detected_at DESC;
