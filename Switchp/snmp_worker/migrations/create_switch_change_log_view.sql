-- Create view for per-switch change logging
-- This makes it easy to query historical changes per switch

CREATE OR REPLACE VIEW switch_change_log AS
SELECT 
    pch.id,
    pch.device_id,
    d.name as switch_name,
    d.ip_address as switch_ip,
    pch.port_number,
    pch.change_type,
    pch.old_value,
    pch.new_value,
    pch.detected_at,
    pch.alarm_created,
    pch.alarm_id,
    a.severity as alarm_severity,
    a.status as alarm_status
FROM port_change_history pch
JOIN snmp_devices d ON pch.device_id = d.id
LEFT JOIN alarms a ON pch.alarm_id = a.id
ORDER BY pch.detected_at DESC;

-- Example queries:

-- Get all changes for a specific switch:
-- SELECT * FROM switch_change_log WHERE switch_name = 'SW35-BALO' ORDER BY detected_at DESC LIMIT 100;

-- Get recent changes for all switches:
-- SELECT * FROM switch_change_log WHERE detected_at > DATE_SUB(NOW(), INTERVAL 24 HOUR);

-- Get changes by type:
-- SELECT * FROM switch_change_log WHERE change_type = 'description_changed' ORDER BY detected_at DESC;

-- Get changes that created alarms:
-- SELECT * FROM switch_change_log WHERE alarm_created = TRUE ORDER BY detected_at DESC;
