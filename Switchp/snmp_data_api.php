<?php
/**
 * SNMP Data API
 * Fetches data collected by the SNMP worker and provides it to the web interface
 */

require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

header('Content-Type: application/json');

$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'get_devices':
            getDevices($conn);
            break;
            
        case 'get_device_details':
            $deviceId = isset($_GET['device_id']) ? intval($_GET['device_id']) : 0;
            getDeviceDetails($conn, $deviceId);
            break;
            
        case 'get_port_status':
            $deviceId = isset($_GET['device_id']) ? intval($_GET['device_id']) : 0;
            getPortStatus($conn, $deviceId);
            break;
            
        case 'get_alarms':
            getActiveAlarms($conn);
            break;
            
        case 'sync_to_switches':
            syncToSwitches($conn, $auth);
            break;
            
        case 'php_vlan_sync':
            phpVlanSync($conn);
            break;

        case 'cleanup_phantom_ports':
            cleanupPhantomPorts($conn);
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
 * Get all SNMP devices
 */
function getDevices($conn) {
    $sql = "SELECT 
                id, name, ip_address, vendor, model, status, enabled,
                total_ports, last_poll_time, last_successful_poll,
                created_at, updated_at
            FROM snmp_devices 
            ORDER BY name";
    
    $result = $conn->query($sql);
    $devices = [];
    
    while ($row = $result->fetch_assoc()) {
        $devices[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'devices' => $devices
    ]);
}

/**
 * Get device details with latest polling data
 */
function getDeviceDetails($conn, $deviceId) {
    // Get device info
    $stmt = $conn->prepare("SELECT * FROM snmp_devices WHERE id = ?");
    $stmt->bind_param("i", $deviceId);
    $stmt->execute();
    $device = $stmt->get_result()->fetch_assoc();
    
    if (!$device) {
        throw new Exception('Device not found');
    }
    
    // Get latest polling data
    $stmt = $conn->prepare("SELECT * FROM device_polling_data 
                           WHERE device_id = ? 
                           ORDER BY poll_timestamp DESC 
                           LIMIT 10");
    $stmt->bind_param("i", $deviceId);
    $stmt->execute();
    $pollingHistory = [];
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $pollingHistory[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'device' => $device,
        'polling_history' => $pollingHistory
    ]);
}

/**
 * Get port status for a device
 */
function getPortStatus($conn, $deviceId) {
    $stmt = $conn->prepare("
        SELECT 
            port_number, port_name, port_alias, port_description,
            admin_status, oper_status, port_speed, port_mtu,
            vlan_id, vlan_name, mac_address, mac_addresses,
            last_seen, poll_timestamp
        FROM port_status_data 
        WHERE device_id = ?
        AND id IN (
            SELECT MAX(id)
            FROM port_status_data
            WHERE device_id = ?
            GROUP BY port_number
        )
        ORDER BY port_number
    ");
    $stmt->bind_param("ii", $deviceId, $deviceId);
    $stmt->execute();
    
    $ports = [];
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $ports[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'ports' => $ports
    ]);
}

/**
 * Get active alarms
 */
function getActiveAlarms($conn) {
    $sql = "SELECT 
                a.id, a.device_id, a.alarm_type, a.severity, a.status,
                a.port_number, a.title, a.message,
                a.occurrence_count, a.first_occurrence, a.last_occurrence,
                d.name as device_name, d.ip_address as device_ip
            FROM alarms a
            LEFT JOIN snmp_devices d ON a.device_id = d.id
            WHERE a.status = 'ACTIVE'
            ORDER BY a.severity DESC, a.last_occurrence DESC";
    
    $result = $conn->query($sql);
    $alarms = [];
    
    while ($row = $result->fetch_assoc()) {
        $alarms[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'alarms' => $alarms
    ]);
}

/**
 * Sync SNMP worker data to main switches table
 */
function syncToSwitches($conn, $auth) {
    $user = $auth->getUser();
    $synced = 0;
    $errors = [];
    
    $conn->begin_transaction();
    
    try {
        // Get all active SNMP devices
        $result = $conn->query("SELECT * FROM snmp_devices WHERE enabled = 1");
        
        while ($snmpDevice = $result->fetch_assoc()) {
            // Check if switch exists in main table
            $stmt = $conn->prepare("SELECT id FROM switches WHERE ip = ?");
            $stmt->bind_param("s", $snmpDevice['ip_address']);
            $stmt->execute();
            $existingSwitch = $stmt->get_result()->fetch_assoc();
            
            if ($existingSwitch) {
                // Update existing switch
                $stmt = $conn->prepare("UPDATE switches SET 
                    name = ?, brand = ?, model = ?, ports = ?, status = ?
                    WHERE id = ?");
                
                $status = strtoupper($snmpDevice['status']) === 'ONLINE' ? 'online' : 'offline';
                $stmt->bind_param("sssisi", 
                    $snmpDevice['name'],
                    $snmpDevice['vendor'],
                    $snmpDevice['model'],
                    $snmpDevice['total_ports'],
                    $status,
                    $existingSwitch['id']
                );
                $stmt->execute();
                $switchId = $existingSwitch['id'];
                
            } else {
                // Insert new switch
                $stmt = $conn->prepare("INSERT INTO switches 
                    (name, brand, model, ports, ip, status) 
                    VALUES (?, ?, ?, ?, ?, 'online')");
                
                $stmt->bind_param("sssis",
                    $snmpDevice['name'],
                    $snmpDevice['vendor'],
                    $snmpDevice['model'],
                    $snmpDevice['total_ports'],
                    $snmpDevice['ip_address']
                );
                $stmt->execute();
                $switchId = $conn->insert_id;
            }
            
            // Sync port data – use MAX(id) per port to avoid the MAX(poll_timestamp)
            // bug where microsecond-apart inserts cause only the last port to match.
            $portStmt = $conn->prepare("
                SELECT * FROM port_status_data
                WHERE id IN (
                    SELECT MAX(id)
                    FROM port_status_data
                    WHERE device_id = ?
                    GROUP BY port_number
                )
            ");
            $portStmt->bind_param("i", $snmpDevice['id']);
            $portStmt->execute();
            $ports = $portStmt->get_result();
            
            // VLAN ID → port type mapping (same as UI VLAN_TYPE_MAP)
            $vlanTypeMap = [
                50 => 'DEVICE',
                254 => 'SERVER',
                70 => 'AP',
                80 => 'KAMERA',
                120 => 'OTOMASYON',
                130 => 'IPTV',
                140 => 'SANTRAL',
            ];
            
            while ($port = $ports->fetch_assoc()) {
                $snmpAlias = trim($port['port_alias'] ?? '');
                $snmpName  = trim($port['port_name']  ?? '');
                $isUp = ($port['oper_status'] === 'up');
                $operStatus = $isUp ? 'up' : 'down';
                $meaningfulTypes = ['DEVICE','SERVER','AP','KAMERA','IPTV','OTOMASYON','SANTRAL','FIBER','ETHERNET','HUB'];

                // Check if port exists (also fetch current type/device/ip to preserve user data)
                $checkStmt = $conn->prepare("SELECT id, type, device, ip FROM ports WHERE switch_id = ? AND port_no = ?");
                $checkStmt->bind_param("ii", $switchId, $port['port_number']);
                $checkStmt->execute();
                $existingPort = $checkStmt->get_result()->fetch_assoc();

                // Determine type:
                // - DOWN: preserve existing meaningful type
                // - UP + known VLAN → mapped device type
                // - UP + unknown VLAN (not 1) → "VLAN X" (red)
                // - UP + no/default VLAN → preserve existing meaningful type (transient failure)
                if (!$isUp) {
                    $existingType = $existingPort ? $existingPort['type'] : null;
                    if ($existingType && (in_array($existingType, $meaningfulTypes) || strpos($existingType, 'VLAN ') === 0)) {
                        $type = $existingType;  // preserve
                    } else {
                        $type = 'EMPTY';
                    }
                } elseif (!empty($port['vlan_id']) && isset($vlanTypeMap[(int)$port['vlan_id']])) {
                    $type = $vlanTypeMap[(int)$port['vlan_id']];
                } elseif (!empty($port['vlan_id']) && (int)$port['vlan_id'] !== 1) {
                    // Non-default VLAN not in map → show as "VLAN X"
                    $type = 'VLAN ' . (int)$port['vlan_id'];
                } else {
                    // vlan_id is null or 1 (CBS350 native default VLAN):
                    // Preserve existing meaningful type; do NOT perpetuate stale 'VLAN X'.
                    $existingType = $existingPort ? $existingPort['type'] : null;
                    if ($existingType && in_array($existingType, $meaningfulTypes)) {
                        $type = $existingType;
                    } else {
                        $type = 'DEVICE'; // safe default for native/unknown VLAN
                    }
                }

                if ($existingPort) {
                    if ($isUp) {
                        // Port UP: update type/oper_status/mac.
                        // Preserve user-set device name and IP:
                        //   Only use SNMP alias if it's a real description (not "GEX")
                        $existingDevice = trim($existingPort['device'] ?? '');
                        $useAlias = $snmpAlias && stripos($snmpAlias, 'GE') !== 0;
                        $newDevice = $useAlias ? $snmpAlias : ($existingDevice ?: $snmpName);
                        $updateStmt = $conn->prepare("UPDATE ports SET 
                            type = ?, oper_status = ?, device = ?, mac = ?
                            WHERE id = ?");
                        $updateStmt->bind_param("ssssi", 
                            $type, $operStatus, $newDevice, $port['mac_address'], $existingPort['id']
                        );
                        $updateStmt->execute();
                    } else {
                        // Port is DOWN: update type+oper_status, preserve device/ip/mac/connection_info_preserved
                        $updateStmt = $conn->prepare("UPDATE ports SET type = ?, oper_status = ? WHERE id = ?");
                        $updateStmt->bind_param("ssi", $type, $operStatus, $existingPort['id']);
                        $updateStmt->execute();
                    }
                } else {
                    // Insert port
                    $insertStmt = $conn->prepare("INSERT INTO ports 
                        (switch_id, port_no, type, oper_status, device, mac) 
                        VALUES (?, ?, ?, ?, ?, ?)");
                    $insertStmt->bind_param("iissss",
                        $switchId, $port['port_number'], $type, $operStatus,
                        ($snmpAlias ?: $snmpName), $port['mac_address']
                    );
                    $insertStmt->execute();
                }
            }
            
            $synced++;
        }
        
        $conn->commit();
        
        // Log activity
        $auth->logActivity(
            $user['id'],
            $user['username'],
            'snmp_sync',
            "SNMP worker verilerinden $synced cihaz senkronize edildi"
        );
        
        echo json_encode([
            'success' => true,
            'message' => "$synced cihaz başarıyla senkronize edildi",
            'synced_count' => $synced
        ]);
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
}

/**
 * PHP SNMP VLAN Sync
 *
 * Uses PHP SNMP extension (same as snmp_test.php) to directly read the
 * VLAN egress mask from each switch and update port_status_data.vlan_id.
 * This is the GUARANTEED fallback when the Python worker's VLAN detection
 * returns 1 for all ports.
 *
 * Logic mirrors snmp_test.php lines 151-183:
 *   - Walk 1.3.6.1.2.1.17.7.1.4.2.1.4 (egress mask)
 *   - Parse binary bitmask: for each port 1-28, check bit in mask bytes
 *   - port's primary_vlan = last non-1 VLAN it belongs to in egress map
 *   - Update port_status_data.vlan_id + ports.type
 */
function phpVlanSync($conn) {
    if (!extension_loaded('snmp')) {
        echo json_encode(['success' => false, 'error' => 'PHP SNMP extension not loaded']);
        return;
    }

    $vlanTypeMap = [
        50 => 'DEVICE', 254 => 'SERVER', 70 => 'AP', 80 => 'KAMERA',
        120 => 'OTOMASYON', 130 => 'IPTV', 140 => 'SANTRAL',
    ];

    $devices = $conn->query("SELECT * FROM snmp_devices WHERE enabled = 1")->fetch_all(MYSQLI_ASSOC);
    $updated = 0;
    $errors  = [];

    foreach ($devices as $dev) {
        try {
            // Build SNMP object (mirrors snmp_test.php config)
            if ($dev['snmp_version'] === '3') {
                $authProto = (strtoupper($dev['snmp_v3_auth_protocol'] ?? 'SHA') === 'MD5') ? 'MD5' : 'SHA';
                $privProto = (strtoupper($dev['snmp_v3_priv_protocol'] ?? 'AES') === 'DES') ? 'DES' : 'AES';
                $snmp = new SNMP(SNMP::VERSION_3, $dev['ip_address'],
                    $dev['snmp_v3_username'] ?? 'snmpuser');
                $engineId = $dev['snmp_engine_id'] ?? '';
                $snmp->setSecurity('authPriv', $authProto,
                    $dev['snmp_v3_auth_password'] ?? '',
                    $privProto, $dev['snmp_v3_priv_password'] ?? '',
                    $engineId, '');
            } else {
                $snmp = new SNMP(SNMP::VERSION_2c, $dev['ip_address'],
                    $dev['snmp_community'] ?? 'public');
            }
            $snmp->valueretrieval = SNMP_VALUE_PLAIN; // raw binary, no type prefix
            $snmp->oid_increasing_check = false;
            $snmp->quick_print = true;

            // Walk egress mask (same OID snmp_test.php uses)
            $snmp->exceptions_enabled = true;
            try {
                $egress = $snmp->walk('1.3.6.1.2.1.17.7.1.4.2.1.4');
            } catch (SNMPException $e) {
                $errors[] = "{$dev['name']}: SNMP walk hatası: " . $e->getMessage();
                continue;
            }
            if (!$egress || !is_array($egress)) {
                $errors[] = "{$dev['name']}: egress walk returned nothing";
                continue;
            }

            // Use total_ports from snmp_devices (CBS350-24FP = 28, etc.)
            // Fall back to mask byte length * 8 to handle any switch model.
            $numPorts = !empty($dev['total_ports']) ? (int)$dev['total_ports'] : 0;
            if ($numPorts < 1) {
                // Determine from the first mask's byte length
                $firstMask = reset($egress);
                $numPorts  = max(28, strlen($firstMask) * 8);
            }

            // Build port → primary_vlan map (mirrors snmp_test.php logic)
            $portVlan = []; // port_num => last non-1 vlan_id
            foreach ($egress as $oid => $mask) {
                if (!preg_match('/\.(\d+)\.(\d+)$/', $oid, $m)) continue;
                $vlan_id = (int)$m[2];
                $mask_len = strlen($mask);
                for ($port = 1; $port <= $numPorts; $port++) {
                    $byte_pos = (int)(($port - 1) / 8);
                    $bit_pos  = 7 - (($port - 1) % 8);
                    if ($byte_pos < $mask_len && ((ord($mask[$byte_pos]) >> $bit_pos) & 1)) {
                        // prefer non-1 VLAN; keep overwriting so last non-1 wins
                        if ($vlan_id != 1) {
                            $portVlan[$port] = $vlan_id;
                        } elseif (!isset($portVlan[$port])) {
                            $portVlan[$port] = 1;
                        }
                    }
                }
            }

            if (empty($portVlan)) {
                $errors[] = "{$dev['name']}: could not parse any port VLANs from egress mask";
                continue;
            }

            // Find matching switch in main table
            $swStmt = $conn->prepare("SELECT id FROM switches WHERE ip = ?");
            $swStmt->bind_param("s", $dev['ip_address']);
            $swStmt->execute();
            $sw = $swStmt->get_result()->fetch_assoc();
            $switchId = $sw ? $sw['id'] : null;

            foreach ($portVlan as $port => $vlan_id) {
                // Update port_status_data.vlan_id (for badge)
                $upd = $conn->prepare("
                    UPDATE port_status_data SET vlan_id = ?
                    WHERE device_id = ? AND port_number = ?
                    AND id = (
                        SELECT max_id FROM (
                            SELECT MAX(id) AS max_id FROM port_status_data
                            WHERE device_id = ? AND port_number = ?
                        ) t
                    )
                ");
                $upd->bind_param("iiiii", $vlan_id, $dev['id'], $port, $dev['id'], $port);
                $upd->execute();

                // Update ports.type directly (for display badge)
                if ($switchId) {
                    $type = isset($vlanTypeMap[$vlan_id]) ? $vlanTypeMap[$vlan_id]
                          : ($vlan_id != 1 ? "VLAN $vlan_id" : null);
                    if ($type) {
                        $tUpd = $conn->prepare("UPDATE ports SET type = ? WHERE switch_id = ? AND port_no = ?");
                        $tUpd->bind_param("sii", $type, $switchId, $port);
                        $tUpd->execute();
                    }
                }
                $updated++;
            }
        } catch (Exception $e) {
            $errors[] = "{$dev['name']}: " . $e->getMessage();
        }
    }

    echo json_encode([
        'success' => true,
        'updated_ports' => $updated,
        'errors' => $errors,
    ]);
}

/**
 * Cleanup phantom ports: DELETE ports with port_no > switches.ports
 * Fixes stale rows when switch port count changes (e.g. 84→52 for C9200L).
 */
function cleanupPhantomPorts($conn) {
    $details = [];

    // Step 1: Sync switches.ports from snmp_devices.total_ports
    // (autosync may not have run yet, or a stale value remained in the DB)
    $syncSql = "
        UPDATE switches s
        JOIN snmp_devices sd ON sd.name = s.name
        SET s.ports = sd.total_ports
        WHERE sd.total_ports > 0
          AND (s.ports IS NULL OR s.ports = 0 OR s.ports != sd.total_ports)
    ";
    if (!$conn->query($syncSql)) {
        throw new Exception('Port sync hatası: ' . $conn->error);
    }
    $synced = $conn->affected_rows;
    if ($synced > 0) {
        $details[] = "switches.ports güncellendi: {$synced} switch";
    }

    // Step 2: Delete phantom ports where port_no > switches.ports
    $sql = "
        SELECT s.id AS switch_id, s.name, s.ports AS max_ports,
               MAX(p.port_no) AS max_db_port
        FROM switches s
        JOIN ports p ON p.switch_id = s.id
        WHERE s.ports > 0
        GROUP BY s.id
        HAVING MAX(p.port_no) > s.ports
    ";
    $result = $conn->query($sql);
    if (!$result) {
        throw new Exception('Sorgu hatası: ' . $conn->error);
    }
    $deleted_total = 0;
    while ($row = $result->fetch_assoc()) {
        $sw_id    = (int)$row['switch_id'];
        $max_port = (int)$row['max_ports'];
        $stmt = $conn->prepare("DELETE FROM ports WHERE switch_id = ? AND port_no > ?");
        if (!$stmt) {
            $details[] = "{$row['name']}: hazırlama hatası";
            continue;
        }
        $stmt->bind_param("ii", $sw_id, $max_port);
        if (!$stmt->execute()) {
            $details[] = "{$row['name']}: silme hatası - " . $stmt->error;
            continue;
        }
        $deleted = $stmt->affected_rows;
        $deleted_total += $deleted;
        $details[] = "{$row['name']}: {$deleted} fantom port silindi (>{$max_port})";
    }

    // Step 3: Also clean port_status_data for stale phantom port entries
    $psdSql = "
        DELETE psd FROM port_status_data psd
        JOIN snmp_devices sd ON psd.device_id = sd.id
        WHERE sd.total_ports > 0
          AND psd.port_number > sd.total_ports
    ";
    $conn->query($psdSql);
    $psdDeleted = (int)$conn->affected_rows;
    if ($psdDeleted > 0) {
        $details[] = "port_status_data: {$psdDeleted} eski port kaydı silindi";
    }

    echo json_encode([
        'success' => true,
        'deleted' => $deleted_total,
        'details' => $details,
    ]);
}
