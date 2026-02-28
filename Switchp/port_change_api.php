<?php
/**
 * Port Change Alarms API
 * Handles fetching and managing port change alarms (MAC movements, VLAN changes, etc.)
 */

require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

header('Content-Type: application/json');

$action = $_GET['action'] ?? $_POST['action'] ?? '';

try {
    switch ($action) {
        case 'get_active_alarms':
            getActiveAlarms($conn);
            break;
            
        case 'get_port_changes':
            $deviceId = isset($_GET['device_id']) ? intval($_GET['device_id']) : 0;
            $portNumber = isset($_GET['port_number']) ? intval($_GET['port_number']) : 0;
            getPortChanges($conn, $deviceId, $portNumber);
            break;
            
        case 'acknowledge_alarm':
            // Accept both GET and POST for compatibility
            $alarmId = isset($_REQUEST['alarm_id']) ? intval($_REQUEST['alarm_id']) : 0;
            $ackType = isset($_REQUEST['ack_type']) ? $_REQUEST['ack_type'] : 'known_change';
            $note = isset($_REQUEST['note']) ? $_REQUEST['note'] : '';
            acknowledgeAlarm($conn, $auth, $alarmId, $ackType, $note);
            break;
            
        case 'bulk_acknowledge':
            // Bulk acknowledge multiple alarms
            $alarmIds = isset($_REQUEST['alarm_ids']) ? $_REQUEST['alarm_ids'] : [];
            $ackType = isset($_REQUEST['ack_type']) ? $_REQUEST['ack_type'] : 'known_change';
            $note = isset($_REQUEST['note']) ? $_REQUEST['note'] : '';
            bulkAcknowledgeAlarms($conn, $auth, $alarmIds, $ackType, $note);
            break;
            
        case 'silence_alarm':
            // Accept both GET and POST for compatibility
            $alarmId = isset($_REQUEST['alarm_id']) ? intval($_REQUEST['alarm_id']) : 0;
            $duration = isset($_REQUEST['duration']) ? intval($_REQUEST['duration']) : (isset($_REQUEST['duration_hours']) ? intval($_REQUEST['duration_hours']) : 24);
            silenceAlarm($conn, $auth, $alarmId, $duration);
            break;
            
        case 'unsilence_alarm':
            $alarmId = isset($_REQUEST['alarm_id']) ? intval($_REQUEST['alarm_id']) : 0;
            if ($alarmId > 0) {
                // Primary update: Clear silence_until (column always exists)
                $updateSql = "UPDATE alarms SET silence_until = NULL WHERE id = ?";
                $stmt = $conn->prepare($updateSql);
                $stmt->bind_param('i', $alarmId);
                
                if ($stmt->execute()) {
                    // Optional: Also clear is_silenced if column exists (won't break if it doesn't)
                    $conn->query("UPDATE alarms SET is_silenced = 0 WHERE id = $alarmId");
                    echo json_encode(['success' => true, 'message' => 'Alarm unsilenced successfully']);
                } else {
                    echo json_encode(['success' => false, 'error' => $stmt->error]);
                }
                $stmt->close();
            } else {
                echo json_encode(['success' => false, 'error' => 'Invalid alarm ID']);
            }
            break;
            
        case 'get_alarm_details':
            $alarmId = isset($_GET['alarm_id']) ? intval($_GET['alarm_id']) : 0;
            getAlarmDetails($conn, $alarmId);
            break;
            
        case 'get_mac_history':
            $macAddress = isset($_GET['mac_address']) ? $_GET['mac_address'] : '';
            getMACHistory($conn, $macAddress);
            break;
            
        case 'get_port_history':
            $deviceId = isset($_GET['device_id']) ? intval($_GET['device_id']) : 0;
            $portNumber = isset($_GET['port_number']) ? intval($_GET['port_number']) : 0;
            getPortHistory($conn, $deviceId, $portNumber);
            break;
            
        case 'get_recently_changed_ports':
            $hours = isset($_GET['hours']) ? intval($_GET['hours']) : 24;
            getRecentlyChangedPorts($conn, $hours);
            break;
        
        case 'create_description_alarm':
            // Create alarm when port description is manually changed via web UI
            $data = json_decode(file_get_contents("php://input"), true);
            createDescriptionChangeAlarm($conn, $data);
            break;

        case 'check_mac_previous_port':
            $deviceId  = isset($_GET['device_id'])   ? intval($_GET['device_id'])   : 0;
            $macAddress = isset($_GET['mac_address']) ? trim($_GET['mac_address'])  : '';
            $newPort   = isset($_GET['port_number'])  ? intval($_GET['port_number']) : 0;
            checkMacPreviousPort($conn, $deviceId, $macAddress, $newPort);
            break;

        case 'check_device_in_registry':
            $macAddress = isset($_GET['mac_address']) ? trim($_GET['mac_address']) : '';
            checkDeviceInRegistry($conn, $macAddress);
            break;

        case 'move_mac_to_port':
            $data = json_decode(file_get_contents("php://input"), true) ?: [];
            moveMacToPort($conn, $auth, $data);
            break;

        case 'register_device_for_alarm':
            $data = json_decode(file_get_contents("php://input"), true) ?: [];
            registerDeviceForAlarm($conn, $auth, $data);
            break;

        default:
            throw new Exception('Invalid action');
    }
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}

/**
 * Get active alarms with port change details
 */
function getActiveAlarms($conn) {
    // Check if from_port and to_port columns exist (backwards compatibility)
    $columns_to_select = "a.id, a.device_id, a.alarm_type, a.severity, a.status,
                a.port_number, a.title, a.message, a.details,
                a.occurrence_count, a.first_occurrence, a.last_occurrence,
                a.acknowledged_at, a.acknowledged_by, a.acknowledgment_type,
                a.silence_until, a.mac_address, a.old_value, a.new_value";
    
    // Try to check if columns exist
    $result = $conn->query("SHOW COLUMNS FROM alarms LIKE 'from_port'");
    if ($result && $result->num_rows > 0) {
        $columns_to_select .= ", a.from_port, a.to_port";
    } else {
        // Columns don't exist yet, use NULL
        $columns_to_select .= ", NULL as from_port, NULL as to_port";
    }
    
    $sql = "SELECT 
                $columns_to_select,
                d.name as device_name, d.ip_address as device_ip,
                CASE 
                    WHEN a.silence_until > NOW() THEN 1
                    ELSE 0
                END as is_silenced,
                CASE
                    WHEN a.alarm_type IN ('mac_moved', 'mac_added', 'vlan_changed', 'description_changed') THEN 1
                    ELSE 0
                END as is_port_change
            FROM alarms a
            LEFT JOIN snmp_devices d ON a.device_id = d.id
            WHERE a.status = 'ACTIVE'
            ORDER BY 
                CASE a.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    WHEN 'INFO' THEN 5
                END,
                a.last_occurrence DESC";
    
    $result = $conn->query($sql);
    $alarms = [];
    
    while ($row = $result->fetch_assoc()) {
        $alarms[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'alarms' => $alarms,
        'total_count' => count($alarms),
        'port_change_count' => count(array_filter($alarms, function($a) { 
            return $a['is_port_change'] == 1; 
        }))
    ]);
}

/**
 * Get port change history
 */
function getPortChanges($conn, $deviceId, $portNumber = null) {
    $sql = "SELECT 
                pch.id, pch.device_id, pch.port_number, pch.change_type,
                pch.change_timestamp, pch.old_value, pch.new_value,
                pch.old_mac_address, pch.new_mac_address,
                pch.old_vlan_id, pch.new_vlan_id,
                pch.old_description, pch.new_description,
                pch.from_device_id, pch.from_port_number,
                pch.to_device_id, pch.to_port_number,
                pch.change_details, pch.alarm_created, pch.alarm_id,
                d.name as device_name,
                fd.name as from_device_name,
                td.name as to_device_name
            FROM port_change_history pch
            LEFT JOIN snmp_devices d ON pch.device_id = d.id
            LEFT JOIN snmp_devices fd ON pch.from_device_id = fd.id
            LEFT JOIN snmp_devices td ON pch.to_device_id = td.id
            WHERE pch.device_id = ?";
    
    $params = [$deviceId];
    $types = 'i';
    
    if ($portNumber) {
        $sql .= " AND pch.port_number = ?";
        $params[] = $portNumber;
        $types .= 'i';
    }
    
    $sql .= " ORDER BY pch.change_timestamp DESC LIMIT 100";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $changes = [];
    
    while ($row = $result->fetch_assoc()) {
        $changes[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'changes' => $changes
    ]);
}

/**
 * Acknowledge an alarm
 */
function acknowledgeAlarm($conn, $auth, $alarmId, $ackType, $note) {
    $user = $auth->getUser();
    
    $conn->begin_transaction();
    
    try {
        // Get alarm
        $stmt = $conn->prepare("SELECT * FROM alarms WHERE id = ?");
        $stmt->bind_param("i", $alarmId);
        $stmt->execute();
        $alarm = $stmt->get_result()->fetch_assoc();
        
        if (!$alarm) {
            throw new Exception('Alarm not found');
        }
        
        if ($ackType === 'known_change') {
            // Mark as acknowledged
            $stmt = $conn->prepare("
                UPDATE alarms 
                SET status = 'ACKNOWLEDGED',
                    acknowledged_at = NOW(),
                    acknowledged_by = ?,
                    acknowledgment_type = 'known_change',
                    updated_at = NOW()
                WHERE id = ?
            ");
            $stmt->bind_param("si", $user['username'], $alarmId);
            $stmt->execute();
            
            // Add to whitelist if MAC address and port are present
            if (!empty($alarm['mac_address']) && !empty($alarm['port_number'])) {
                $deviceName = getDeviceName($conn, $alarm['device_id']);
                addToWhitelist(
                    $conn,
                    $deviceName,
                    $alarm['port_number'],
                    $alarm['mac_address'],
                    $user['username'],
                    $note
                );
            }
            
            // For MAC mismatch alarms: update the MAC address in ports table to the new value
            // This saves the new (actual) MAC on the switch port so future SNMP polls don't re-alarm
            if (!empty($alarm['new_value']) && !empty($alarm['port_number']) &&
                in_array($alarm['alarm_type'], ['mac_moved', 'mac_added'])) {
                $newMac = $alarm['new_value'];
                $portNum = $alarm['port_number'];
                $deviceId = $alarm['device_id'];
                $updateMacStmt = $conn->prepare("
                    UPDATE ports p
                    JOIN switches s ON p.switch_id = s.id
                    JOIN snmp_devices sd ON s.name = sd.name
                    SET p.mac = ?
                    WHERE sd.id = ? AND p.port_no = ?
                ");
                if ($updateMacStmt) {
                    $updateMacStmt->bind_param("sii", $newMac, $deviceId, $portNum);
                    $updateMacStmt->execute();
                    $updateMacStmt->close();
                }
            }
            
            // Add to alarm history
            $stmt = $conn->prepare("
                INSERT INTO alarm_history 
                (alarm_id, old_status, new_status, change_reason, change_message, changed_at)
                VALUES (?, 'ACTIVE', 'ACKNOWLEDGED', 'Acknowledged by user', ?, NOW())
            ");
            $message = "Acknowledged as known change by {$user['username']}: $note";
            $stmt->bind_param("is", $alarmId, $message);
            $stmt->execute();
            
        } else if ($ackType === 'false_alarm') {
            // Mark as acknowledged (false alarm)
            $stmt = $conn->prepare("
                UPDATE alarms 
                SET status = 'ACKNOWLEDGED',
                    acknowledged_at = NOW(),
                    acknowledged_by = ?,
                    acknowledgment_type = 'false_alarm',
                    updated_at = NOW()
                WHERE id = ?
            ");
            $stmt->bind_param("si", $user['username'], $alarmId);
            $stmt->execute();
            
            // Add to alarm history
            $stmt = $conn->prepare("
                INSERT INTO alarm_history 
                (alarm_id, old_status, new_status, change_reason, change_message, changed_at)
                VALUES (?, 'ACTIVE', 'ACKNOWLEDGED', 'Marked as false alarm', ?, NOW())
            ");
            $message = "Marked as false alarm by {$user['username']}: $note";
            $stmt->bind_param("is", $alarmId, $message);
            $stmt->execute();
            
        } else if ($ackType === 'resolved') {
            // Mark as resolved
            $stmt = $conn->prepare("
                UPDATE alarms 
                SET status = 'RESOLVED',
                    resolved_at = NOW(),
                    resolved_by = ?,
                    updated_at = NOW()
                WHERE id = ?
            ");
            $stmt->bind_param("si", $user['username'], $alarmId);
            $stmt->execute();
            
            // Add to alarm history
            $stmt = $conn->prepare("
                INSERT INTO alarm_history 
                (alarm_id, old_status, new_status, change_reason, change_message, changed_at)
                VALUES (?, 'ACTIVE', 'RESOLVED', 'Resolved by user', ?, NOW())
            ");
            $message = "Resolved by {$user['username']}: $note";
            $stmt->bind_param("is", $alarmId, $message);
            $stmt->execute();
        }
        
        // Log activity
        $auth->logActivity(
            $user['id'],
            $user['username'],
            'alarm_acknowledge',
            "Acknowledged alarm #{$alarmId} as $ackType"
        );
        
        $conn->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Alarm acknowledged successfully'
        ]);
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
}

/**
 * Silence an alarm (remove red highlighting but keep it active)
 */
function silenceAlarm($conn, $auth, $alarmId, $durationHours) {
    $user = $auth->getUser();
    
    $stmt = $conn->prepare("
        UPDATE alarms 
        SET acknowledgment_type = 'silenced',
            silence_until = DATE_ADD(NOW(), INTERVAL ? HOUR),
            acknowledged_at = NOW(),
            acknowledged_by = ?,
            updated_at = NOW()
        WHERE id = ?
    ");
    $stmt->bind_param("isi", $durationHours, $user['username'], $alarmId);
    $stmt->execute();
    
    // Log activity
    $auth->logActivity(
        $user['id'],
        $user['username'],
        'alarm_silence',
        "Silenced alarm #{$alarmId} for {$durationHours} hours"
    );
    
    echo json_encode([
        'success' => true,
        'message' => "Alarm silenced for {$durationHours} hours"
    ]);
}

/**
 * Get MAC address movement history
 */
function getMACHistory($conn, $macAddress) {
    $sql = "SELECT 
                mat.*,
                cd.name as current_device_name,
                pd.name as previous_device_name,
                (SELECT COUNT(*) FROM port_change_history pch 
                 WHERE pch.old_mac_address = mat.mac_address 
                 OR pch.new_mac_address = mat.mac_address) as total_changes
            FROM mac_address_tracking mat
            LEFT JOIN snmp_devices cd ON mat.current_device_id = cd.id
            LEFT JOIN snmp_devices pd ON mat.previous_device_id = pd.id
            WHERE mat.mac_address = ?";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $macAddress);
    $stmt->execute();
    
    $tracking = $stmt->get_result()->fetch_assoc();
    
    // Get change history
    $sql = "SELECT 
                pch.*,
                d.name as device_name,
                fd.name as from_device_name,
                td.name as to_device_name
            FROM port_change_history pch
            LEFT JOIN snmp_devices d ON pch.device_id = d.id
            LEFT JOIN snmp_devices fd ON pch.from_device_id = fd.id
            LEFT JOIN snmp_devices td ON pch.to_device_id = td.id
            WHERE pch.old_mac_address = ? OR pch.new_mac_address = ?
            ORDER BY pch.change_timestamp DESC
            LIMIT 50";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $macAddress, $macAddress);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $history = [];
    
    while ($row = $result->fetch_assoc()) {
        $history[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'tracking' => $tracking,
        'history' => $history
    ]);
}

/**
 * Get port change history
 */
function getPortHistory($conn, $deviceId, $portNumber) {
    // Get snapshots
    $sql = "SELECT *
            FROM port_snapshot
            WHERE device_id = ? AND port_number = ?
            ORDER BY snapshot_timestamp DESC
            LIMIT 50";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $deviceId, $portNumber);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $snapshots = [];
    
    while ($row = $result->fetch_assoc()) {
        $snapshots[] = $row;
    }
    
    // Get changes
    $sql = "SELECT 
                pch.*,
                d.name as device_name
            FROM port_change_history pch
            LEFT JOIN snmp_devices d ON pch.device_id = d.id
            WHERE pch.device_id = ? AND pch.port_number = ?
            ORDER BY pch.change_timestamp DESC
            LIMIT 50";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $deviceId, $portNumber);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $changes = [];
    
    while ($row = $result->fetch_assoc()) {
        $changes[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'snapshots' => $snapshots,
        'changes' => $changes
    ]);
}

/**
 * Get recently changed ports (for highlighting in red)
 */
function getRecentlyChangedPorts($conn, $hours = 24) {
    $sql = "SELECT DISTINCT
                pch.device_id,
                pch.port_number,
                d.name as device_name,
                d.ip_address,
                COUNT(pch.id) as change_count,
                MAX(pch.change_timestamp) as last_change,
                GROUP_CONCAT(DISTINCT pch.change_type) as change_types
            FROM port_change_history pch
            LEFT JOIN snmp_devices d ON pch.device_id = d.id
            WHERE pch.change_timestamp > DATE_SUB(NOW(), INTERVAL ? HOUR)
            GROUP BY pch.device_id, pch.port_number, d.name, d.ip_address
            ORDER BY MAX(pch.change_timestamp) DESC";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $hours);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $changed_ports = [];
    
    while ($row = $result->fetch_assoc()) {
        // Create a key for easy lookup
        $key = $row['device_id'] . '_' . $row['port_number'];
        $changed_ports[$key] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'changed_ports' => $changed_ports,
        'hours' => $hours,
        'count' => count($changed_ports)
    ]);
}

/**
 * Get detailed information about a specific alarm
 */
function getAlarmDetails($conn, $alarmId) {
    if ($alarmId <= 0) {
        echo json_encode([
            'success' => false,
            'error' => 'Invalid alarm ID'
        ]);
        return;
    }
    
    $sql = "SELECT 
                a.id, a.device_id, a.alarm_type, a.severity, a.status,
                a.port_number, a.title, a.message, a.details,
                a.occurrence_count, a.first_occurrence, a.last_occurrence,
                a.acknowledged_at, a.acknowledged_by, a.acknowledgment_type,
                a.resolved_at, a.resolved_by,
                a.silence_until, a.mac_address, a.old_value, a.new_value,
                a.created_at, a.updated_at,
                d.name as device_name, d.ip_address as device_ip,
                CASE 
                    WHEN a.silence_until > NOW() THEN 1
                    ELSE 0
                END as is_silenced
            FROM alarms a
            LEFT JOIN snmp_devices d ON a.device_id = d.id
            WHERE a.id = ?";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $alarmId);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $alarm = $result->fetch_assoc();
    
    if (!$alarm) {
        echo json_encode([
            'success' => false,
            'error' => 'Alarm not found'
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'alarm' => $alarm
    ]);
}

/**
 * Get device name by ID
 */
function getDeviceName($conn, $deviceId) {
    $stmt = $conn->prepare("SELECT name FROM snmp_devices WHERE id = ?");
    $stmt->bind_param("i", $deviceId);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    return $row ? $row['name'] : '';
}

/**
 * Add MAC+Port combination to whitelist
 */
function addToWhitelist($conn, $deviceName, $portNumber, $macAddress, $acknowledgedBy, $note) {
    try {
        // Normalize MAC address to uppercase for consistency with Python worker
        $macAddress = strtoupper($macAddress);
        
        // Check if already whitelisted
        $stmt = $conn->prepare("
            SELECT id FROM acknowledged_port_mac
            WHERE device_name = ? AND port_number = ? AND mac_address = ?
        ");
        $stmt->bind_param("sis", $deviceName, $portNumber, $macAddress);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            // Already whitelisted, update note
            $stmt = $conn->prepare("
                UPDATE acknowledged_port_mac
                SET note = ?, acknowledged_by = ?, updated_at = NOW()
                WHERE device_name = ? AND port_number = ? AND mac_address = ?
            ");
            $stmt->bind_param("sssis", $note, $acknowledgedBy, $deviceName, $portNumber, $macAddress);
            $stmt->execute();
        } else {
            // Add to whitelist
            $stmt = $conn->prepare("
                INSERT INTO acknowledged_port_mac
                (device_name, port_number, mac_address, acknowledged_by, note)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->bind_param("sisss", $deviceName, $portNumber, $macAddress, $acknowledgedBy, $note);
            $stmt->execute();
        }
        
        return true;
    } catch (Exception $e) {
        error_log("Failed to add to whitelist: " . $e->getMessage());
        return false;
    }
}

/**
 * Bulk acknowledge multiple alarms
 */
function bulkAcknowledgeAlarms($conn, $auth, $alarmIds, $ackType, $note) {
    $user = $auth->getUser();
    
    // Parse alarm IDs if it's a JSON string
    if (is_string($alarmIds)) {
        $alarmIds = json_decode($alarmIds, true);
    }
    
    if (!is_array($alarmIds) || empty($alarmIds)) {
        echo json_encode([
            'success' => false,
            'error' => 'No alarm IDs provided'
        ]);
        return;
    }
    
    $conn->begin_transaction();
    
    try {
        $successCount = 0;
        $failedCount = 0;
        
        foreach ($alarmIds as $alarmId) {
            $alarmId = intval($alarmId);
            if ($alarmId <= 0) {
                $failedCount++;
                continue;
            }
            
            // Get alarm
            $stmt = $conn->prepare("SELECT * FROM alarms WHERE id = ?");
            $stmt->bind_param("i", $alarmId);
            $stmt->execute();
            $alarm = $stmt->get_result()->fetch_assoc();
            
            if (!$alarm) {
                $failedCount++;
                continue;
            }
            
            // Mark as acknowledged
            $stmt = $conn->prepare("
                UPDATE alarms 
                SET status = 'ACKNOWLEDGED',
                    acknowledged_at = NOW(),
                    acknowledged_by = ?,
                    acknowledgment_type = ?,
                    updated_at = NOW()
                WHERE id = ?
            ");
            $stmt->bind_param("ssi", $user['username'], $ackType, $alarmId);
            $stmt->execute();
            
            // Add to whitelist if MAC address and port are present
            if (!empty($alarm['mac_address']) && !empty($alarm['port_number'])) {
                $deviceName = getDeviceName($conn, $alarm['device_id']);
                addToWhitelist(
                    $conn,
                    $deviceName,
                    $alarm['port_number'],
                    $alarm['mac_address'],
                    $user['username'],
                    $note
                );
            }
            
            // For MAC mismatch alarms: update the MAC address in ports table to the new value
            if (!empty($alarm['new_value']) && !empty($alarm['port_number']) &&
                in_array($alarm['alarm_type'], ['mac_moved', 'mac_added']) &&
                $ackType === 'known_change') {
                $newMac = $alarm['new_value'];
                $portNum = $alarm['port_number'];
                $deviceId = $alarm['device_id'];
                $updateMacStmt = $conn->prepare("
                    UPDATE ports p
                    JOIN switches s ON p.switch_id = s.id
                    JOIN snmp_devices sd ON s.name = sd.name
                    SET p.mac = ?
                    WHERE sd.id = ? AND p.port_no = ?
                ");
                if ($updateMacStmt) {
                    $updateMacStmt->bind_param("sii", $newMac, $deviceId, $portNum);
                    $updateMacStmt->execute();
                    $updateMacStmt->close();
                }
            }
            
            // Add to alarm history
            $stmt = $conn->prepare("
                INSERT INTO alarm_history 
                (alarm_id, old_status, new_status, change_reason, change_message, changed_at)
                VALUES (?, 'ACTIVE', 'ACKNOWLEDGED', 'Bulk acknowledged by user', ?, NOW())
            ");
            $message = "Bulk acknowledged by {$user['username']}: $note";
            $stmt->bind_param("is", $alarmId, $message);
            $stmt->execute();
            
            $successCount++;
        }
        
        // Log activity
        $auth->logActivity(
            $user['id'],
            $user['username'],
            'bulk_alarm_acknowledge',
            "Bulk acknowledged $successCount alarms"
        );
        
        $conn->commit();
        
        echo json_encode([
            'success' => true,
            'message' => "$successCount alarms acknowledged successfully",
            'acknowledged_count' => $successCount,
            'failed_count' => $failedCount
        ]);
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
}


/**
 * Create alarm for manual port description change
 * Called when user updates port description via web UI
 */
function createDescriptionChangeAlarm($conn, $data) {
    $switchId = isset($data['switchId']) ? intval($data['switchId']) : 0;
    $portNo = isset($data['portNo']) ? intval($data['portNo']) : 0;
    $oldDescription = isset($data['oldDescription']) ? trim($data['oldDescription']) : '';
    $newDescription = isset($data['newDescription']) ? trim($data['newDescription']) : '';
    
    if ($switchId <= 0 || $portNo <= 0) {
        throw new Exception("Invalid switch ID or port number");
    }
    
    // Get switch info from switches table
    $switchStmt = $conn->prepare("SELECT name, ip FROM switches WHERE id = ?");
    $switchStmt->bind_param("i", $switchId);
    $switchStmt->execute();
    $switchResult = $switchStmt->get_result();
    $switch = $switchResult->fetch_assoc();
    $switchStmt->close();
    
    if (!$switch) {
        throw new Exception("Switch not found");
    }
    
    $deviceName = $switch['name'];
    $deviceIp = $switch['ip'];
    
    // Get SNMP device_id (may not exist if switch not in SNMP system)
    $snmpDeviceId = null;
    $snmpStmt = $conn->prepare("SELECT id FROM snmp_devices WHERE ip_address = ?");
    $snmpStmt->bind_param("s", $deviceIp);
    $snmpStmt->execute();
    $snmpResult = $snmpStmt->get_result();
    if ($snmpRow = $snmpResult->fetch_assoc()) {
        $snmpDeviceId = $snmpRow['id'];
    }
    $snmpStmt->close();
    
    if (!$snmpDeviceId) {
        // No SNMP device - can't create alarm in SNMP system
        echo json_encode([
            'success' => false,
            'message' => 'Switch not configured in SNMP system',
            'info' => 'Description updated but alarm not created (switch not in SNMP monitoring)'
        ]);
        return;
    }
    
    // Create alarm message
    $title = "Port $portNo açıklaması değişti";
    $oldDesc = $oldDescription ?: '(boş)';
    $newDesc = $newDescription ?: '(boş)';
    $message = "Port $portNo ($deviceName) açıklaması manuel olarak değiştirildi.\n\n";
    $message .= "Eski değer: '$oldDesc'\n";
    $message .= "Yeni değer: '$newDesc'";
    
    // Check if similar alarm exists (within last hour) - avoid duplicates
    $checkStmt = $conn->prepare("
        SELECT id, occurrence_count FROM alarms 
        WHERE device_id = ? 
        AND port_number = ? 
        AND alarm_type = 'description_changed'
        AND status = 'ACTIVE'
        AND first_occurrence > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        LIMIT 1
    ");
    $checkStmt->bind_param("ii", $snmpDeviceId, $portNo);
    $checkStmt->execute();
    $checkResult = $checkStmt->get_result();
    
    if ($existingAlarm = $checkResult->fetch_assoc()) {
        // Update existing alarm - increment counter
        $updateStmt = $conn->prepare("
            UPDATE alarms 
            SET occurrence_count = occurrence_count + 1,
                last_occurrence = NOW(),
                message = ?,
                new_value = ?,
                updated_at = NOW()
            WHERE id = ?
        ");
        $updateStmt->bind_param("ssi", $message, $newDescription, $existingAlarm['id']);
        $updateStmt->execute();
        $updateStmt->close();
        
        $checkStmt->close();
        
        echo json_encode([
            'success' => true,
            'message' => 'Existing alarm updated',
            'alarm_id' => $existingAlarm['id'],
            'action' => 'updated'
        ]);
    } else {
        // Create new alarm
        $checkStmt->close();
        
        $insertStmt = $conn->prepare("
            INSERT INTO alarms (
                device_id, 
                port_number, 
                alarm_type, 
                severity, 
                status,
                title, 
                message,
                old_value,
                new_value,
                first_occurrence,
                last_occurrence,
                occurrence_count,
                created_at,
                updated_at
            ) VALUES (?, ?, 'description_changed', 'MEDIUM', 'ACTIVE', ?, ?, ?, ?, NOW(), NOW(), 1, NOW(), NOW())
        ");
        $insertStmt->bind_param("iissss", 
            $snmpDeviceId, 
            $portNo, 
            $title, 
            $message,
            $oldDescription,
            $newDescription
        );
        
        if ($insertStmt->execute()) {
            $alarmId = $insertStmt->insert_id;
            $insertStmt->close();
            
            // Update port_status_data table to sync description
            try {
                $syncStmt = $conn->prepare("
                    UPDATE port_status_data 
                    SET port_alias = ?,
                        last_seen = NOW()
                    WHERE device_id = ? AND port_number = ?
                ");
                $syncStmt->bind_param("sii", $newDescription, $snmpDeviceId, $portNo);
                $syncStmt->execute();
                $syncStmt->close();
            } catch (Exception $e) {
                // Table might not exist or no row - not critical
                error_log("Could not sync port_status_data: " . $e->getMessage());
            }
            
            // Record in port_change_history
            try {
                $changeDetails = "Port $portNo açıklaması manuel olarak değiştirildi: '$oldDesc' → '$newDesc'";
                
                $historyStmt = $conn->prepare("
                    INSERT INTO port_change_history (
                        device_id,
                        port_number,
                        change_type,
                        change_timestamp,
                        old_description,
                        new_description,
                        change_details,
                        alarm_created,
                        alarm_id
                    ) VALUES (?, ?, 'DESCRIPTION_CHANGED', NOW(), ?, ?, ?, 1, ?)
                ");
                $historyStmt->bind_param("iisssi", 
                    $snmpDeviceId, 
                    $portNo, 
                    $oldDescription, 
                    $newDescription, 
                    $changeDetails,
                    $alarmId
                );
                $historyStmt->execute();
                $historyStmt->close();
            } catch (Exception $e) {
                // Table might not exist - not critical
                error_log("Could not record change history: " . $e->getMessage());
            }
            
            echo json_encode([
                'success' => true,
                'message' => 'Alarm created successfully',
                'alarm_id' => $alarmId,
                'action' => 'created'
            ]);
        } else {
            throw new Exception("Failed to create alarm: " . $conn->error);
        }
    }
}

/**
 * Check if a MAC address was previously seen on another port of the same switch
 */
function checkMacPreviousPort($conn, $deviceId, $macAddress, $newPort) {
    if ($deviceId <= 0 || empty($macAddress)) {
        echo json_encode(['success' => false, 'error' => 'Invalid parameters']);
        return;
    }
    $macAddress = strtoupper($macAddress);

    // Check ports table for another port with this MAC on the same switch
    $stmt = $conn->prepare("
        SELECT p.port_no, p.mac, s.name as switch_name, s.ip as switch_ip
        FROM ports p
        JOIN switches s ON p.switch_id = s.id
        JOIN snmp_devices sd ON s.name = sd.name
        WHERE sd.id = ? AND UPPER(p.mac) = ? AND p.port_no != ?
        LIMIT 1
    ");
    $stmt->bind_param("isi", $deviceId, $macAddress, $newPort);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($row) {
        echo json_encode([
            'success' => true,
            'found' => true,
            'previous_port' => $row['port_no'],
            'switch_name'   => $row['switch_name'],
            'switch_ip'     => $row['switch_ip'],
        ]);
    } else {
        echo json_encode(['success' => true, 'found' => false]);
    }
}

/**
 * Check if a MAC address exists in the device import registry
 */
function checkDeviceInRegistry($conn, $macAddress) {
    if (empty($macAddress)) {
        echo json_encode(['success' => false, 'error' => 'MAC address required']);
        return;
    }
    $macAddress = strtoupper($macAddress);

    $stmt = $conn->prepare("
        SELECT mac_address, ip_address, device_name, user_name, location, department, notes
        FROM mac_device_registry
        WHERE UPPER(mac_address) = ?
        LIMIT 1
    ");
    $stmt->bind_param("s", $macAddress);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($row) {
        echo json_encode(['success' => true, 'found' => true, 'device' => $row]);
    } else {
        echo json_encode(['success' => true, 'found' => false]);
    }
}

/**
 * Move a MAC address from old port to new port, update DB and write JSON history
 */
function moveMacToPort($conn, $auth, $data) {
    $alarmId  = isset($data['alarm_id'])   ? intval($data['alarm_id'])   : 0;
    $oldPort  = isset($data['old_port'])   ? intval($data['old_port'])   : 0;
    $newPort  = isset($data['new_port'])   ? intval($data['new_port'])   : 0;
    $mac      = isset($data['mac_address']) ? strtoupper(trim($data['mac_address'])) : '';
    $deviceId = isset($data['device_id'])  ? intval($data['device_id'])  : 0;

    if ($alarmId <= 0 || $newPort <= 0 || empty($mac) || $deviceId <= 0) {
        echo json_encode(['success' => false, 'error' => 'Invalid parameters']);
        return;
    }

    $user = $auth->getUser();
    $conn->begin_transaction();
    try {
        // Get device info
        $stmt = $conn->prepare("SELECT name, ip_address FROM snmp_devices WHERE id = ?");
        $stmt->bind_param("i", $deviceId);
        $stmt->execute();
        $device = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        // Get alarm old_value (expected MAC on old port)
        $stmt = $conn->prepare("SELECT old_value, port_number FROM alarms WHERE id = ?");
        $stmt->bind_param("i", $alarmId);
        $stmt->execute();
        $alarm = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $oldMac = $alarm ? strtoupper($alarm['old_value']) : '';
        if ($oldPort <= 0 && $alarm) {
            // old_port was not provided; derive from alarm port or db
            $oldPort = intval($alarm['port_number']);
        }

        // Clear MAC from old port
        if ($oldPort > 0) {
            $stmt = $conn->prepare("
                UPDATE ports p
                JOIN switches s ON p.switch_id = s.id
                JOIN snmp_devices sd ON s.name = sd.name
                SET p.mac = NULL
                WHERE sd.id = ? AND p.port_no = ?
            ");
            $stmt->bind_param("ii", $deviceId, $oldPort);
            $stmt->execute();
            $stmt->close();
        }

        // Set MAC on new port
        $stmt = $conn->prepare("
            UPDATE ports p
            JOIN switches s ON p.switch_id = s.id
            JOIN snmp_devices sd ON s.name = sd.name
            SET p.mac = ?
            WHERE sd.id = ? AND p.port_no = ?
        ");
        $stmt->bind_param("sii", $mac, $deviceId, $newPort);
        $stmt->execute();
        $stmt->close();

        // Close alarm
        $stmt = $conn->prepare("
            UPDATE alarms
            SET status = 'ACKNOWLEDGED', acknowledged_at = NOW(),
                acknowledged_by = ?, acknowledgment_type = 'mac_moved', updated_at = NOW()
            WHERE id = ?
        ");
        $stmt->bind_param("si", $user['username'], $alarmId);
        $stmt->execute();
        $stmt->close();

        // Add to whitelist
        if ($device) {
            addToWhitelist($conn, $device['name'], $newPort, $mac, $user['username'], 'MAC taşındı');
        }

        // Write JSON history
        $historyEntry = [
            'timestamp'   => date('Y-m-d H:i:s'),
            'switch'      => $device ? $device['name']       : '',
            'switch_ip'   => $device ? $device['ip_address'] : '',
            'old_port'    => (string)$oldPort,
            'new_port'    => (string)$newPort,
            'old_mac'     => $oldMac,
            'new_mac'     => $mac,
            'action'      => 'mac_moved',
            'approved_by' => $user['username'],
        ];
        writeMacHistory($historyEntry);

        $conn->commit();
        echo json_encode(['success' => true, 'message' => 'MAC porta taşındı ve alarm kapatıldı']);
    } catch (Exception $e) {
        $conn->rollback();
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
}

/**
 * Register a new device (or confirm existing) and assign MAC to port, then close alarm
 */
function registerDeviceForAlarm($conn, $auth, $data) {
    $alarmId    = isset($data['alarm_id'])    ? intval($data['alarm_id'])              : 0;
    $mac        = isset($data['mac_address']) ? strtoupper(trim($data['mac_address'])) : '';
    $deviceId   = isset($data['device_id'])   ? intval($data['device_id'])             : 0;
    $portNumber = isset($data['port_number']) ? intval($data['port_number'])           : 0;
    $deviceName = isset($data['device_name']) ? trim($data['device_name'])             : '';
    $ipAddress  = isset($data['ip_address'])  ? trim($data['ip_address'])              : '';
    $location   = isset($data['location'])    ? trim($data['location'])                : '';
    $description = isset($data['description']) ? trim($data['description'])            : '';

    if ($alarmId <= 0 || empty($mac) || $deviceId <= 0 || $portNumber <= 0 || empty($deviceName)) {
        echo json_encode(['success' => false, 'error' => 'Eksik alanlar var. Lütfen tüm zorunlu alanları doldurun.']);
        return;
    }

    $user = $auth->getUser();
    $conn->begin_transaction();
    try {
        // Upsert into mac_device_registry
        $stmt = $conn->prepare("
            INSERT INTO mac_device_registry
                (mac_address, ip_address, device_name, location, notes, source, created_by)
            VALUES (?, ?, ?, ?, ?, 'manual', ?)
            ON DUPLICATE KEY UPDATE
                ip_address   = VALUES(ip_address),
                device_name  = VALUES(device_name),
                location     = VALUES(location),
                notes        = VALUES(notes),
                source       = 'manual',
                updated_by   = VALUES(created_by)
        ");
        $stmt->bind_param("ssssss", $mac, $ipAddress, $deviceName, $location, $description, $user['username']);
        $stmt->execute();
        $stmt->close();

        // Assign MAC to port
        $stmt = $conn->prepare("
            UPDATE ports p
            JOIN switches s ON p.switch_id = s.id
            JOIN snmp_devices sd ON s.name = sd.name
            SET p.mac = ?
            WHERE sd.id = ? AND p.port_no = ?
        ");
        $stmt->bind_param("sii", $mac, $deviceId, $portNumber);
        $stmt->execute();
        $stmt->close();

        // Get device name for whitelist
        $stmt = $conn->prepare("SELECT name, ip_address FROM snmp_devices WHERE id = ?");
        $stmt->bind_param("i", $deviceId);
        $stmt->execute();
        $device = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        // Close alarm
        $stmt = $conn->prepare("
            UPDATE alarms
            SET status = 'ACKNOWLEDGED', acknowledged_at = NOW(),
                acknowledged_by = ?, acknowledgment_type = 'device_registered', updated_at = NOW()
            WHERE id = ?
        ");
        $stmt->bind_param("si", $user['username'], $alarmId);
        $stmt->execute();
        $stmt->close();

        // Add to whitelist
        if ($device) {
            addToWhitelist($conn, $device['name'], $portNumber, $mac, $user['username'], 'Cihaz kaydedildi: ' . $deviceName);
        }

        // Write JSON history
        $historyEntry = [
            'timestamp'   => date('Y-m-d H:i:s'),
            'switch'      => $device ? $device['name']       : '',
            'switch_ip'   => $device ? $device['ip_address'] : '',
            'old_port'    => '',
            'new_port'    => (string)$portNumber,
            'old_mac'     => '',
            'new_mac'     => $mac,
            'action'      => 'device_registered',
            'approved_by' => $user['username'],
        ];
        writeMacHistory($historyEntry);

        $conn->commit();
        echo json_encode(['success' => true, 'message' => 'Cihaz kaydedildi ve alarm kapatıldı']);
    } catch (Exception $e) {
        $conn->rollback();
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
}

/**
 * Append a MAC history entry to the JSON log file (with file lock)
 */
function writeMacHistory($entry) {
    $dir  = __DIR__ . '/logs';
    $file = $dir . '/mac_history.json';

    // Ensure directory exists
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }

    $fp = fopen($file, 'c+');
    if (!$fp) {
        error_log("writeMacHistory: cannot open $file");
        return;
    }
    if (flock($fp, LOCK_EX)) {
        $size = @filesize($file);
        $existing = [];
        if ($size !== false && $size > 0) {
            $raw = fread($fp, $size);
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $existing = $decoded;
            }
        }
        array_unshift($existing, $entry); // newest first
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($existing, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
}

