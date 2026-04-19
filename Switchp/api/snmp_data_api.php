<?php
/**
 * SNMP Data API
 * Fetches data collected by the SNMP worker and provides it to the web interface
 */

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

// Release PHP session lock so concurrent AJAX requests are not serialized.
session_write_close();

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
    
} catch (Throwable $e) {
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
        // Mask IP address — never expose real IPs to the client
        $row['ip_address'] = $row['ip_address'] ? '***' : '';
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
            // Guard: JSON-named "devices" are phantom artefacts from the old
            // sync_virtual_core_switches() bug.  Skip them entirely to prevent
            // creating new phantom switch rows.
            if (!empty($snmpDevice['name']) && ltrim($snmpDevice['name'])[0] === '{') {
                continue;
            }

            // Check if switch exists in main table — first by IP, then by
            // normalized name so that a manually-added "SW31 -RUBY" (spaces)
            // is not duplicated as a separate "SW31-RUBY" SNMP-discovered entry.
            $stmt = $conn->prepare("SELECT id, rack_id, is_virtual FROM switches WHERE ip = ?");
            $stmt->bind_param("s", $snmpDevice['ip_address']);
            $stmt->execute();
            $ipMatch = $stmt->get_result()->fetch_assoc();

            // Also look for a normalized-name match (strips spaces from both sides)
            $stmt2 = $conn->prepare("SELECT id, rack_id, is_virtual FROM switches WHERE REPLACE(name,' ','') = REPLACE(?,' ','')");
            $stmt2->bind_param("s", $snmpDevice['name']);
            $stmt2->execute();
            $nameMatch = $stmt2->get_result()->fetch_assoc();

            if ($ipMatch && $nameMatch && $ipMatch['id'] !== $nameMatch['id']) {
                // Both exist as different rows → merge: keep the rack-assigned (manually-placed)
                // one, delete the other. Fall back to keeping the lower id (older = manual).
                $keeper   = ($nameMatch['rack_id'] && !$ipMatch['rack_id']) ? $nameMatch : $ipMatch;
                $discard  = ($keeper['id'] === $ipMatch['id'])              ? $nameMatch : $ipMatch;

                // Reassign panel/fiber connections to the keeper
                $pu = $conn->prepare("UPDATE patch_ports SET connected_switch_id = ? WHERE connected_switch_id = ?");
                $pu->bind_param("ii", $keeper['id'], $discard['id']); $pu->execute();
                $fu = $conn->prepare("UPDATE fiber_ports SET connected_switch_id = ? WHERE connected_switch_id = ?");
                $fu->bind_param("ii", $keeper['id'], $discard['id']); $fu->execute();
                $su = $conn->prepare("UPDATE snmp_config SET switch_id = ? WHERE switch_id = ?");
                $su->bind_param("ii", $keeper['id'], $discard['id']); $su->execute();

                // Delete the discarded switch (CASCADE removes its orphan ports)
                $del = $conn->prepare("DELETE FROM switches WHERE id = ?");
                $del->bind_param("i", $discard['id']); $del->execute();

                $existingSwitch = $keeper;
                // Make sure the keeper has the correct IP for future IP-based lookups
                $fixIp = $conn->prepare("UPDATE switches SET ip = ? WHERE id = ?");
                $fixIp->bind_param("si", $snmpDevice['ip_address'], $keeper['id']); $fixIp->execute();

            } elseif ($ipMatch) {
                $existingSwitch = $ipMatch;

            } elseif ($nameMatch) {
                $existingSwitch = $nameMatch;
                // Fix missing IP so future syncs use the faster IP lookup
                $fixIp = $conn->prepare("UPDATE switches SET ip = ? WHERE id = ?");
                $fixIp->bind_param("si", $snmpDevice['ip_address'], $nameMatch['id']); $fixIp->execute();

            } else {
                $existingSwitch = null;
            }

            // If no match yet, check whether the SNMP device name is a prefix of a seeded
            // virtual/core switch (e.g. physical "CHAMADA-9606-CORESW" vs. seeded
            // "CHAMADA-9606-CORESW-1" / "CHAMADA-9606-CORESW-2").
            // The physical chassis should not create a duplicate phantom switch.
            if (!$existingSwitch) {
                $likePattern = $snmpDevice['name'] . '%';
                $prefixStmt = $conn->prepare(
                    "SELECT id FROM switches WHERE name LIKE ? AND (is_core = 1 OR is_virtual = 1) LIMIT 1"
                );
                $prefixStmt->bind_param("s", $likePattern);
                $prefixStmt->execute();
                $prefixMatch = $prefixStmt->get_result()->fetch_assoc();
                if ($prefixMatch) {
                    // This SNMP device is the physical chassis behind a virtual/core switch.
                    // Skip entirely — do not create a phantom switch, do not overwrite
                    // the carefully seeded virtual switch data.
                    continue;
                }
            }

            if ($existingSwitch) {
                // Never overwrite seeded virtual/core switches — they are managed
                // manually and must not be renamed by autosync.
                if (!empty($existingSwitch['is_virtual'])) {
                    // Do NOT sync ports either: virtual switch ports are seeded
                    // manually and must not be overwritten by physical SNMP data.
                    continue;
                } else {
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
                }
                
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
            
            // Sync port data – use INNER JOIN on aggregated max_id to avoid
            // the inefficient WHERE id IN (SELECT MAX(id) ...) double-scan.
            // device_id is filtered inside the subquery; the JOIN ensures only
            // the matching device's rows are returned (single ? placeholder).
            $portStmt = $conn->prepare("
                SELECT psd.* FROM port_status_data psd
                INNER JOIN (
                    SELECT device_id, port_number, MAX(id) AS max_id
                    FROM port_status_data
                    WHERE device_id = ?
                    GROUP BY port_number
                ) latest ON psd.device_id = latest.device_id
                        AND psd.port_number = latest.port_number
                        AND psd.id = latest.max_id
            ");
            $portStmt->bind_param("i", $snmpDevice['id']);
            $portStmt->execute();
            $ports = $portStmt->get_result();
            
            // VLAN ID → port type mapping (same as UI VLAN_TYPE_MAP)
            $vlanTypeMap = [
                30  => 'GUEST',
                40  => 'VIP',
                50  => 'DEVICE',
                70  => 'AP',
                80  => 'KAMERA',
                110 => 'SES',
                120 => 'OTOMASYON',
                130 => 'IPTV',
                140 => 'SANTRAL',
                150 => 'JACKPOT',
                254 => 'SERVER',
                1500 => 'DRGT',
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
                // - DOWN: VLAN data first (mirrors autosync_service.py priority), then preserve meaningful
                // - UP + known VLAN → mapped device type
                // - UP + unknown VLAN (not 1) → "VLAN X" (red)
                // - UP + no/default VLAN → preserve existing meaningful type (transient failure)
                if (!$isUp) {
                    // Priority: VLAN from port_status_data (ground truth) > meaningful type > EMPTY
                    $portVlanId = !empty($port['vlan_id']) ? (int)$port['vlan_id'] : 0;
                    if ($portVlanId > 1 && isset($vlanTypeMap[$portVlanId])) {
                        $type = $vlanTypeMap[$portVlanId];
                    } elseif ($portVlanId > 1) {
                        $type = 'VLAN ' . $portVlanId;
                    } else {
                        $existingType = $existingPort ? $existingPort['type'] : null;
                        if ($existingType && (in_array($existingType, $meaningfulTypes) || strpos($existingType, 'VLAN ') === 0)) {
                            $type = $existingType;  // preserve when no VLAN data
                        } else {
                            $type = 'EMPTY';
                        }
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
    // SNMP walks across all devices can take well over 30 s on a large network.
    // Raise the PHP execution limit so the process is not killed mid-walk
    // (which would cause an ERR_CONNECTION_RESET to the caller).
    set_time_limit(300);

    if (!extension_loaded('snmp')) {
        echo json_encode(['success' => false, 'error' => 'PHP SNMP extension not loaded']);
        return;
    }

    $vlanTypeMap = [
        30 => 'GUEST', 40 => 'VIP', 50 => 'DEVICE', 70 => 'AP', 80 => 'KAMERA',
        110 => 'SES', 120 => 'OTOMASYON', 130 => 'IPTV', 140 => 'SANTRAL',
        150 => 'JACKPOT', 254 => 'SERVER', 1500 => 'DRGT',
    ];

    $devRes  = $conn->query("SELECT * FROM snmp_devices WHERE enabled = 1");
    $devices = $devRes ? $devRes->fetch_all(MYSQLI_ASSOC) : [];
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
                // setSecurity order: sec_level, auth_proto, auth_pass, priv_proto, priv_pass,
                //   contextName (6th), contextEngineID (7th).
                // CBS350 requires engineId as the 7th param; 6th (contextName) must be ''.
                $snmp->setSecurity('authPriv', $authProto,
                    $dev['snmp_v3_auth_password'] ?? '',
                    $privProto, $dev['snmp_v3_priv_password'] ?? '',
                    /* contextName */ '', /* contextEngineID */ $engineId);
            } else {
                $snmp = new SNMP(SNMP::VERSION_2c, $dev['ip_address'],
                    $dev['snmp_community'] ?? 'public');
            }
            $snmp->valueretrieval = SNMP_VALUE_PLAIN; // raw binary, no type prefix
            $snmp->oid_increasing_check = false;
            $snmp->quick_print = true;
            // Prevent unreachable devices from blocking the entire sync.
            // 2 s timeout × 2 attempts = 4 s max per device.
            $snmp->timeout = 2000000;
            $snmp->retries = 1;

            // Walk egress mask (dot1qVlanStaticEgressPorts)
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

            // Walk untagged mask (dot1qVlanStaticUntaggedPorts) — used to distinguish
            // access ports (one untagged VLAN) from trunk ports (untagged native VLAN +
            // multiple tagged VLANs).  Mirrors the Python worker's _determine_vlan().
            $untagged = [];
            try {
                $untagged = $snmp->walk('1.3.6.1.2.1.17.7.1.4.2.1.5') ?: [];
            } catch (SNMPException $e) {
                // Non-fatal: fall back to egress-only logic if untagged walk fails.
                $untagged = [];
            }

            // Use total_ports from snmp_devices (CBS350-24FP = 28, CBS350-48P = 52, etc.)
            // Fall back to model-string parsing so we never use IF_NUMBER or raw mask length
            // (both of which can return 200+ for CBS350 due to VLAN sub-interfaces).
            $numPorts = !empty($dev['total_ports']) ? (int)$dev['total_ports'] : 0;
            if ($numPorts < 1) {
                // Try to derive port count from the model name stored in snmp_devices.
                $modelStr = $dev['model'] ?? '';
                if (preg_match('/CBS350-(\d+)[A-Za-z]*-(\d+)G/i', $modelStr, $cbsM)) {
                    $numPorts = (int)$cbsM[1] + (int)$cbsM[2];
                } elseif (preg_match('/CBS350-(\d+)/i', $modelStr, $cbsM)) {
                    $numPorts = (int)$cbsM[1] + 4;
                } else {
                    $numPorts = 28; // legacy default (CBS350-24FP)
                }
            }

            // Helper: parse OctetString bitmap → set of 1-based port numbers.
            $bitmapPorts = function(string $mask, int $maxPort): array {
                $ports = [];
                $maskLen = strlen($mask);
                for ($p = 1; $p <= $maxPort; $p++) {
                    $bytePos = (int)(($p - 1) / 8);
                    $bitPos  = 7 - (($p - 1) % 8);
                    if ($bytePos < $maskLen && ((ord($mask[$bytePos]) >> $bitPos) & 1)) {
                        $ports[] = $p;
                    }
                }
                return $ports;
            };

            // Build per-port VLAN sets from egress and untagged bitmaps.
            // egressVlans[port]   = [ vlan_id, ... ]  (all VLANs whose egress bit is set)
            // untaggedVlans[port] = [ vlan_id, ... ]  (VLANs where traffic leaves untagged)
            $egressVlans   = []; // port => [vlan_id, ...]
            $untaggedVlans = []; // port => [vlan_id, ...]

            foreach ($egress as $oid => $mask) {
                if (!preg_match('/\.(\d+)\.(\d+)$/', $oid, $m)) continue;
                $vlan_id = (int)$m[2];
                foreach ($bitmapPorts($mask, $numPorts) as $port) {
                    $egressVlans[$port][] = $vlan_id;
                }
            }
            foreach ($untagged as $oid => $mask) {
                if (!preg_match('/\.(\d+)\.(\d+)$/', $oid, $m)) continue;
                $vlan_id = (int)$m[2];
                foreach ($bitmapPorts($mask, $numPorts) as $port) {
                    $untaggedVlans[$port][] = $vlan_id;
                }
            }

            // Determine primary VLAN per port using the same logic as the Python
            // worker's _determine_vlan():
            //   - Port has untagged non-1 VLANs only (no other tagged)  → access VLAN
            //   - Port has untagged native VLAN + tagged VLANs (trunk)  → native VLAN
            //   - Port has only tagged VLANs (pure trunk, no native)    → lowest tagged VLAN
            //   - Port only in VLAN 1 → 1
            // This prevents trunk AP ports (native 70 + allowed 30,50,70,140,254) from
            // being assigned VLAN 254 (SERVER) by the old "last non-1 wins" logic.
            $portVlan = [];
            $allPorts = array_unique(array_merge(array_keys($egressVlans), array_keys($untaggedVlans)));
            foreach ($allPorts as $port) {
                $portEgress   = $egressVlans[$port]   ?? [];
                $portUntagged = $untaggedVlans[$port]  ?? [];

                $realUntagged = array_values(array_filter(array_unique($portUntagged), fn($v) => $v != 1));
                $realTagged   = array_values(array_filter(
                    array_unique(array_diff($portEgress, $portUntagged)),
                    fn($v) => $v != 1
                ));

                if (!empty($realUntagged)) {
                    // Use the native/access VLAN (first untagged non-1 VLAN).
                    sort($realUntagged);
                    $portVlan[$port] = $realUntagged[0];
                } elseif (!empty($realTagged)) {
                    // Pure trunk with no untagged VLAN: use lowest tagged VLAN.
                    sort($realTagged);
                    $portVlan[$port] = $realTagged[0];
                } elseif (!empty($portEgress)) {
                    $portVlan[$port] = 1;
                }
            }

            if (empty($portVlan)) {
                $errors[] = "{$dev['name']}: could not parse any port VLANs from egress mask";
                continue;
            }

            // Find matching switch in main table — by IP first, then normalized name
            $swStmt = $conn->prepare("SELECT id FROM switches WHERE ip = ?");
            if (!$swStmt) throw new \RuntimeException("prepare failed: " . $conn->error);
            $swStmt->bind_param("s", $dev['ip_address']);
            $swStmt->execute();
            $sw = $swStmt->get_result()->fetch_assoc();
            if (!$sw) {
                $swStmt2 = $conn->prepare("SELECT id FROM switches WHERE REPLACE(name,' ','') = REPLACE(?,' ','')");
                if (!$swStmt2) throw new \RuntimeException("prepare failed: " . $conn->error);
                $swStmt2->bind_param("s", $dev['name']);
                $swStmt2->execute();
                $sw = $swStmt2->get_result()->fetch_assoc();
                // Fix the IP so future syncs use the faster IP lookup
                if ($sw) {
                    $fixIp2 = $conn->prepare("UPDATE switches SET ip = ? WHERE id = ?");
                    if ($fixIp2) {
                        $fixIp2->bind_param("si", $dev['ip_address'], $sw['id']);
                        $fixIp2->execute();
                    }
                }
            }
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
                if ($upd) {
                    $upd->bind_param("iiiii", $vlan_id, $dev['id'], $port, $dev['id'], $port);
                    $upd->execute();
                }

                // Update ports.type directly (for display badge)
                if ($switchId) {
                    $type = isset($vlanTypeMap[$vlan_id]) ? $vlanTypeMap[$vlan_id]
                          : ($vlan_id != 1 ? "VLAN $vlan_id" : null);
                    if ($type) {
                        $tUpd = $conn->prepare("UPDATE ports SET type = ? WHERE switch_id = ? AND port_no = ?");
                        if ($tUpd) {
                            $tUpd->bind_param("sii", $type, $switchId, $port);
                            $tUpd->execute();
                        }
                    }
                }
                $updated++;
            }
        } catch (Throwable $e) {
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

    // Step 0: Correct CBS350 total_ports that were wrongly set from IF_NUMBER.
    // IF_NUMBER includes VLAN sub-interfaces and can be 200+.  Re-derive the
    // correct value from sys_descr stored in device_polling_data.
    $cbsRows = $conn->query("
        SELECT sd.id, sd.total_ports,
               dp.system_description
        FROM snmp_devices sd
        LEFT JOIN (
            SELECT device_id, system_description
            FROM device_polling_data
            WHERE id IN (SELECT MAX(id) FROM device_polling_data GROUP BY device_id)
        ) dp ON dp.device_id = sd.id
        WHERE sd.model LIKE 'cbs350%' OR sd.model LIKE 'CBS350%'
           OR dp.system_description LIKE '%CBS350%'
    ");
    if ($cbsRows) {
        while ($row = $cbsRows->fetch_assoc()) {
            $sysDescr = $row['system_description'] ?? '';
            $correct = 0;
            if (preg_match('/CBS350-(\d+)[A-Za-z]*-(\d+)G/i', $sysDescr, $m)) {
                $correct = (int)$m[1] + (int)$m[2];
            } elseif (preg_match('/CBS350-(\d+)/i', $sysDescr, $m)) {
                $correct = (int)$m[1] + 4;
            }
            if ($correct > 0 && (int)$row['total_ports'] !== $correct) {
                $upd = $conn->prepare("UPDATE snmp_devices SET total_ports = ? WHERE id = ?");
                $upd->bind_param("ii", $correct, $row['id']);
                $upd->execute();
                if ($upd->affected_rows > 0) {
                    $details[] = "snmp_devices id={$row['id']} ({$sysDescr}): total_ports düzeltildi {$row['total_ports']} → {$correct}";
                }
            }
        }
    }

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
