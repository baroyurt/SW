<?php
// Errors must NOT appear in output – they would corrupt JSON.
// display_errors is off so PHP notices/warnings never reach the output buffer.
// error_reporting is kept high so they are still written to the PHP error log.
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(E_ALL);

include __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

// Release session lock so concurrent requests are not serialized.
session_write_close();

header('Content-Type: application/json; charset=utf-8');

// Connection parser fonksiyonu
function parseConnectionInfo($connectionString) {
    $connections = [];
    
    if (empty($connectionString)) {
        return $connections;
    }
    
    $connectionString = trim($connectionString);
    
    // JSON formatında mı kontrol et
    if (strpos($connectionString, '[') === 0 || strpos($connectionString, '{') === 0) {
        $parsed = json_decode($connectionString, true);
        if (is_array($parsed)) {
            return $parsed;
        }
        // Non-array JSON object: if it's a virtual_core marker, don't treat as a connection list
        if ($parsed !== null && isset($parsed['type']) && in_array($parsed['type'], ['virtual_core', 'virtual_core_reverse'])) {
            return [];
        }
    }
    
    // Eğer JSON değilse, metni parse et
    // Farklı ayraçlarla böl
    $parts = preg_split('/[\r\n,;|]+/', $connectionString);
    
    foreach ($parts as $part) {
        $part = trim($part);
        if (empty($part) || $part === '-' || $part === '[]') continue;
        
        $connection = [
            'device' => $part,
            'ip' => '',
            'mac' => '',
            'type' => 'DEVICE'
        ];
        
        // IP adresi çıkar
        if (preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $part, $ipMatches)) {
            $connection['ip'] = $ipMatches[1];
        }
        
        // MAC adresi çıkar ve formatla
        if (preg_match('/([0-9a-fA-F]{2}[:.\-]?){5,}[0-9a-fA-F]{2}/', $part, $macMatches)) {
            $mac = $macMatches[0];
            $cleanMac = preg_replace('/[^a-fA-F0-9]/', '', $mac);
            if (strlen($cleanMac) === 12) {
                $connection['mac'] = implode(':', str_split($cleanMac, 2));
            }
        }
        
        // Tür belirleme
        $upperPart = strtoupper($part);
        if (strpos($upperPart, 'AP') !== false) {
            $connection['type'] = 'AP';
        } elseif (strpos($upperPart, 'IPTV') !== false) {
            $connection['type'] = 'IPTV';
        } elseif (strpos($upperPart, 'FIBER') !== false) {
            $connection['type'] = 'FIBER';
        } elseif (strpos($upperPart, 'OTOMASYON') !== false) {
            $connection['type'] = 'OTOMASYON';
        } elseif (strpos($upperPart, 'SANTRAL') !== false) {
            $connection['type'] = 'SANTRAL';
        } elseif (strpos($upperPart, 'SERVER') !== false) {
            $connection['type'] = 'SERVER';
        } elseif (strpos($upperPart, 'TELEFON') !== false || strpos($upperPart, 'PHONE') !== false) {
            $connection['type'] = 'PHONE';
        } elseif (strpos($upperPart, 'YAZICI') !== false || strpos($upperPart, 'PRINTER') !== false) {
            $connection['type'] = 'PRINTER';
        } elseif (strpos($upperPart, 'KAMERA') !== false || strpos($upperPart, 'CAMERA') !== false) {
            $connection['type'] = 'CAMERA';
        } elseif (strpos($upperPart, 'HUB') !== false) {
            $connection['type'] = 'HUB';
        }
        
        $connections[] = $connection;
    }
    
    return $connections;
}

// IP/MAC'den HUB olup olmadığını kontrol et
function isHubFromData($ip, $mac, $connectionInfo) {
    if (!empty($connectionInfo) && $connectionInfo !== '[]' && $connectionInfo !== 'null') {
        $connections = parseConnectionInfo($connectionInfo);
        if (count($connections) > 1) {
            return true;
        }
    }
    
    $ipParts = [];
    $macParts = [];
    
    if (!empty($ip)) {
        $ipParts = preg_split('/[\r\n,;\s]+/', $ip);
        $ipParts = array_filter(array_map('trim', $ipParts), function($item) {
            $item = trim($item);
            return !empty($item) && $item !== '-' && filter_var($item, FILTER_VALIDATE_IP);
        });
    }
    
    if (!empty($mac)) {
        $macParts = preg_split('/[\r\n,;\s]+/', $mac);
        $macParts = array_filter(array_map('trim', $macParts), function($item) {
            $item = trim($item);
            return !empty($item) && $item !== '-' && strlen(preg_replace('/[^a-fA-F0-9]/', '', $item)) >= 12;
        });
    }
    
    $validIpCount = count($ipParts);
    $validMacCount = count($macParts);
    
    if (($validIpCount > 1 && $validMacCount >= 0) || ($validMacCount > 1 && $validIpCount >= 0)) {
        return true;
    }
    
    if ((strpos($ip, ',') !== false || strpos($ip, ';') !== false || strpos($ip, "\n") !== false) && $validIpCount <= 1) {
        return false;
    }
    if ((strpos($mac, ',') !== false || strpos($mac, ';') !== false || strpos($mac, "\n") !== false) && $validMacCount <= 1) {
        return false;
    }
    
    return false;
}

try {
    // Racks
    $racksQuery = "SELECT * FROM racks ORDER BY name";
    $racksResult = $conn->query($racksQuery);
    if (!$racksResult) {
        throw new Exception("Rack sorgusu hatası: " . $conn->error);
    }
    $racks = $racksResult->fetch_all(MYSQLI_ASSOC);
    
    // Switches — include SNMP health fields (temperature, CPU, fan, memory) if available
    $switchQuery = "
        SELECT s.id, s.name, s.brand, s.model, s.ports, s.status, s.rack_id,
               s.position_in_rack, s.is_core, s.is_virtual, s.description,
               '***'              AS ip,
               r.name as rack_name, r.location as rack_location,
               COALESCE(sd.temperature_c,
                   (SELECT TOP 1 dpd_t.temperature
                    FROM device_polling_data dpd_t
                    WHERE dpd_t.device_id = sd.id
                      AND dpd_t.temperature IS NOT NULL
                    ORDER BY dpd_t.poll_timestamp DESC))    AS snmp_temperature_c,
               sd.cpu_1min        AS snmp_cpu_1min,
               sd.fan_status      AS snmp_fan_status,
               sd.poe_nominal_w   AS snmp_poe_nominal_w,
               sd.poe_consumed_w  AS snmp_poe_consumed_w,
               (SELECT COUNT(CASE WHEN psd_a.poe_detecting = 1 THEN 1 END)
                FROM port_status_data psd_a WHERE psd_a.device_id = sd.id
                  AND psd_a.poe_detecting IS NOT NULL)    AS snmp_poe_active_ports,
               (SELECT COUNT(psd_t.id)
                FROM port_status_data psd_t WHERE psd_t.device_id = sd.id
                  AND psd_t.poe_detecting IS NOT NULL)    AS snmp_poe_total_ports,
               (SELECT TOP 1 ROUND(dpd.memory_usage, 1)
                FROM device_polling_data dpd
                WHERE dpd.device_id = sd.id
                ORDER BY dpd.poll_timestamp DESC)           AS snmp_memory_usage
        FROM switches s
        LEFT JOIN racks r ON s.rack_id = r.id
        LEFT JOIN snmp_devices sd ON (sd.name = s.name OR sd.ip_address = s.ip)
        ORDER BY s.rack_id, COALESCE(s.position_in_rack, 999), s.name
    ";
    $switchesResult = $conn->query($switchQuery);
    if (!$switchesResult) {
        throw new Exception("Switch sorgusu hatası: " . $conn->error);
    }
    $switches = $switchesResult->fetch_all(MYSQLI_ASSOC);
    
    // Patch Panels
    $patchQuery = "
        SELECT pp.*, r.name as rack_name, r.location,
               (SELECT COUNT(id) FROM patch_ports WHERE panel_id = pp.id) as total_ports_created,
               (SELECT COUNT(id) FROM patch_ports WHERE panel_id = pp.id AND status = 'active') as active_ports
        FROM patch_panels pp
        LEFT JOIN racks r ON pp.rack_id = r.id
        ORDER BY pp.rack_id, COALESCE(pp.position_in_rack, 999), pp.panel_letter
    ";
    $patchResult = $conn->query($patchQuery);
    if (!$patchResult) {
        throw new Exception("Patch panel sorgusu hatası: " . $conn->error);
    }
    $patchPanels = $patchResult->fetch_all(MYSQLI_ASSOC);
    
    // Patch Panel Portları
    $patchPortsQuery = "
        SELECT 
            ppo.*, 
            pp.panel_letter, 
            pp.rack_id, 
            r.name as rack_name,
            ppo.connected_switch_id,
            ppo.connected_switch_port,
            ppo.connection_details,
            s.name as connected_switch_name
        FROM patch_ports ppo
        LEFT JOIN patch_panels pp ON ppo.panel_id = pp.id
        LEFT JOIN racks r ON pp.rack_id = r.id
        LEFT JOIN switches s ON ppo.connected_switch_id = s.id
        ORDER BY pp.rack_id, pp.panel_letter, ppo.port_number
    ";
    $patchPortsResult = $conn->query($patchPortsQuery);
    $patchPorts = [];
    if ($patchPortsResult) {
        while ($port = $patchPortsResult->fetch_assoc()) {
            $panelId = $port['panel_id'];
            if (!isset($patchPorts[$panelId])) {
                $patchPorts[$panelId] = [];
            }
            $patchPorts[$panelId][] = $port;
        }
    }
    
    // Fiber Panels
    $fiberQuery = "
        SELECT fp.*, r.name as rack_name, r.location 
        FROM fiber_panels fp
        LEFT JOIN racks r ON fp.rack_id = r.id
        ORDER BY fp.rack_id, COALESCE(fp.position_in_rack, 999), fp.panel_letter
    ";
    $fiberResult = $conn->query($fiberQuery);
    $fiberPanels = $fiberResult ? $fiberResult->fetch_all(MYSQLI_ASSOC) : [];
    
    // Fiber Ports
    $fiberPortsQuery = "
        SELECT 
            fp.*,
            fpanel.panel_letter,
            fpanel.rack_id,
            r.name as rack_name,
            fp.connected_switch_id,
            fp.connected_switch_port,
            s.name as connected_switch_name,
            fp.connected_fiber_panel_id,
            fp.connected_fiber_panel_port,
            fp2.panel_letter as connected_fiber_panel_letter,
            fp.is_jump_point,
            fp.jump_path,
            fp.connection_details
        FROM fiber_ports fp
        LEFT JOIN fiber_panels fpanel ON fp.panel_id = fpanel.id
        LEFT JOIN racks r ON fpanel.rack_id = r.id
        LEFT JOIN switches s ON fp.connected_switch_id = s.id
        LEFT JOIN fiber_panels fp2 ON fp.connected_fiber_panel_id = fp2.id
        ORDER BY fpanel.rack_id, fpanel.panel_letter, fp.port_number
    ";
    $fiberPortsResult = $conn->query($fiberPortsQuery);
    $fiberPorts = [];
    if ($fiberPortsResult) {
        while ($port = $fiberPortsResult->fetch_assoc()) {
            $panelId = $port['panel_id'];
            if (!isset($fiberPorts[$panelId])) {
                $fiberPorts[$panelId] = [];
            }
            $fiberPorts[$panelId][] = $port;
        }
    }
    
    $validPanelIds = [0];
    $res = $conn->query("SELECT id FROM patch_panels");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $validPanelIds[] = (int)$row['id'];
        }
    }
    $validPanelList = implode(',', $validPanelIds);

    // Ensure ALL tables referenced by portQuery LEFT JOINs exist.
    // On fresh installs or pre-migration deployments some of these may be absent,
    // which would cause the entire portQuery to fail and getData.php to return
    // success:false → the UI shows "Veri yüklenemedi" for ALL data.
    $conn->query("CREATE TABLE IF NOT EXISTS snmp_devices (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        total_ports INT DEFAULT 0,
        status ENUM('online','offline','error') DEFAULT 'offline',
        enabled BOOLEAN DEFAULT TRUE,
        last_poll_time DATETIME DEFAULT NULL,
        snmp_version VARCHAR(10) DEFAULT 'v2c',
        snmp_community VARCHAR(100) DEFAULT 'public',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $conn->query("CREATE TABLE IF NOT EXISTS port_status_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_id INT NOT NULL,
        port_number INT NOT NULL,
        poll_timestamp DATETIME NOT NULL,
        port_alias VARCHAR(255) DEFAULT NULL,
        vlan_id INT DEFAULT NULL,
        vlan_name VARCHAR(255) DEFAULT NULL,
        oper_status ENUM('up','down','testing','unknown','dormant','notPresent','lowerLayerDown') DEFAULT 'down',
        INDEX idx_psd_device (device_id),
        INDEX idx_psd_port (device_id, port_number)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // Add port_alias if table was created by an older migration that omitted it.
    $conn->query("IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='port_status_data' AND COLUMN_NAME='port_alias') BEGIN ALTER TABLE port_status_data ADD port_alias VARCHAR(255) DEFAULT NULL END");
    // Add connection_info to ports if it was created from an older schema that omitted it.
    $conn->query("IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='ports' AND COLUMN_NAME='connection_info') BEGIN ALTER TABLE ports ADD connection_info NVARCHAR(MAX) DEFAULT NULL END");
    // Add is_virtual and is_core to switches if created from an older schema that omitted them.
    $conn->query("IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='switches' AND COLUMN_NAME='is_virtual') BEGIN ALTER TABLE switches ADD is_virtual BIT NOT NULL DEFAULT 0 END");
    $conn->query("IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='switches' AND COLUMN_NAME='is_core') BEGIN ALTER TABLE switches ADD is_core BIT NOT NULL DEFAULT 0 END");
    $conn->query("CREATE TABLE IF NOT EXISTS snmp_uplink_ports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_id INT NOT NULL,
        port_number INT NOT NULL,
        description VARCHAR(255) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_uplink_port (device_id, port_number)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $conn->query("CREATE TABLE IF NOT EXISTS snmp_core_ports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_id INT NOT NULL,
        port_number INT NOT NULL,
        core_switch_name VARCHAR(100) NOT NULL,
        description VARCHAR(255) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_core_port (device_id, port_number)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $conn->query("CREATE TABLE IF NOT EXISTS mac_device_registry (
        id INT AUTO_INCREMENT PRIMARY KEY,
        mac_address VARCHAR(17) NOT NULL,
        ip_address VARCHAR(45) DEFAULT NULL,
        device_name VARCHAR(255) DEFAULT NULL,
        user_name VARCHAR(255) DEFAULT NULL,
        location VARCHAR(255) DEFAULT NULL,
        notes TEXT DEFAULT NULL,
        source ENUM('domain','excel','manual') DEFAULT 'manual',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_mac (mac_address)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Ports with panel info and VLAN data from SNMP
    $portQuery = "
        SELECT 
            p.*,
            p.connected_panel_id,
            p.connected_panel_port,
            p.connection_info_preserved,
            CASE 
                WHEN p.connected_panel_id IN ($validPanelList) THEN 'patch'
                ELSE NULL
            END as panel_type,
            pp.panel_letter as connected_panel_letter,
            pp_rack.name as connected_panel_rack,
            CASE 
                WHEN (p.ip IS NOT NULL AND p.ip != '') 
                  OR (p.mac IS NOT NULL AND p.mac != '') 
                  OR (p.device IS NOT NULL AND p.device != '' AND p.device != 'BOŞ')
                  OR (p.connection_info IS NOT NULL AND p.connection_info != '')
                THEN 1 ELSE 0
            END as is_active,
            psd.vlan_id as snmp_vlan_id,
            psd.vlan_name as snmp_vlan_name,
            psd.psd_oper_status,
            psd.snmp_port_alias,
            psd.poe_detecting  as snmp_poe_detecting,
            psd.poe_power_mw   as snmp_poe_power_mw,
            CASE WHEN sup.port_number IS NOT NULL THEN 1 ELSE 0 END as is_uplink,
            scp.core_switch_name as core_switch_name_fallback,
            s.name  AS sw_name,
            s.is_core AS sw_is_core,
            s.is_virtual AS sw_is_virtual
        FROM ports p
        LEFT JOIN patch_panels pp 
               ON p.connected_panel_id = pp.id 
              AND p.connected_panel_id IN ($validPanelList)
        LEFT JOIN racks pp_rack 
               ON pp.rack_id = pp_rack.id
        LEFT JOIN switches s ON p.switch_id = s.id
        LEFT JOIN snmp_devices sd ON (s.name = sd.name OR s.ip = sd.ip_address)
        LEFT JOIN (
            SELECT psd.device_id, psd.port_number, psd.vlan_id, psd.vlan_name,
                   psd.oper_status AS psd_oper_status, psd.port_alias AS snmp_port_alias,
                   psd.poe_detecting, psd.poe_power_mw
            FROM port_status_data psd
            INNER JOIN (
                SELECT device_id, port_number, MAX(id) AS max_id
                FROM port_status_data
                GROUP BY device_id, port_number
            ) latest ON psd.device_id = latest.device_id
                    AND psd.port_number = latest.port_number
                    AND psd.id = latest.max_id
        ) psd ON sd.id = psd.device_id AND p.port_no = psd.port_number
        LEFT JOIN snmp_uplink_ports sup
               ON sd.id = sup.device_id AND p.port_no = sup.port_number
        LEFT JOIN snmp_core_ports scp
               ON sd.id = scp.device_id AND p.port_no = scp.port_number
        WHERE (GREATEST(COALESCE(sd.total_ports, 0), COALESCE(s.ports, 0)) = 0 OR p.port_no <= GREATEST(COALESCE(sd.total_ports, 0), COALESCE(s.ports, 0)))
        ORDER BY p.switch_id, p.port_no
    ";
    
    $portsResult = $conn->query($portQuery);
    if (!$portsResult) {
        throw new Exception("Port sorgusu hatası: " . $conn->error);
    }

    // Build a reverse lookup: "CoreSW-name:core_port_no" → edge switch info.
    // Used to populate a `core_reverse_fallback` virtual_core_reverse JSON for
    // virtual/core switch ports whose connection_info_preserved is missing/non-JSON.
    // This provides an immediate tooltip fix even before migration 75 / Pass 3 run.
    $coreSwPortToEdge = [];
    $scpRQ = $conn->query("
        SELECT scp.core_switch_name, sd.name AS edge_sw_name, scp.port_number AS edge_port_no
        FROM   snmp_core_ports scp
        JOIN   snmp_devices sd ON sd.id = scp.device_id
        WHERE  scp.core_switch_name LIKE '%|%' OR scp.core_switch_name LIKE '{%'
    ");
    if ($scpRQ) {
        while ($scpRow = $scpRQ->fetch_assoc()) {
            $csName     = trim($scpRow['core_switch_name']);
            $cswName    = '';
            $corePortNo = 0;
            if ($csName !== '' && $csName[0] === '{') {
                // JSON format: {"type":"virtual_core","core_switch_name":"CORESW-2","core_port_no":31,...}
                $vcJson = json_decode($csName, true);
                if ($vcJson && isset($vcJson['core_switch_name'])) {
                    $cswName = $vcJson['core_switch_name'];
                    if (isset($vcJson['core_port_no'])) {
                        $corePortNo = (int)$vcJson['core_port_no'];
                    } elseif (isset($vcJson['core_port_label'])) {
                        $label = $vcJson['core_port_label'];
                        if (preg_match('/(?:GigE\d+)\/(\d+)\/0\/(\d+)$/i', $label, $m)) {
                            $corePortNo = ((int)$m[1] - 1) * 48 + (int)$m[2];
                        } elseif (preg_match('/\/(\d+)$/', $label, $m)) {
                            $corePortNo = (int)$m[1];
                        }
                    }
                }
            } else {
                // Pipe-separated format: "CORESW-2 | TwentyFiveGigE2/1/0/31"
                $parts      = array_map('trim', explode('|', $csName, 2));
                $cswName    = $parts[0];
                $portLabel  = $parts[1] ?? '';
                if (preg_match('/(?:GigE\d+)\/(\d+)\/0\/(\d+)$/i', $portLabel, $m)) {
                    $corePortNo = ((int)$m[1] - 1) * 48 + (int)$m[2];
                } elseif (preg_match('/\/(\d+)$/', $portLabel, $m)) {
                    $corePortNo = (int)$m[1];
                }
            }
            if ($corePortNo > 0 && $cswName !== '') {
                $coreSwPortToEdge[$cswName . ':' . $corePortNo] = [
                    'edge_sw_name' => $scpRow['edge_sw_name'],
                    'edge_port_no' => (int)$scpRow['edge_port_no'],
                ];
            }
        }
    }

    // Load mac_device_registry into memory (keyed by normalised 12-char hex MAC)
    // so that hub port device entries can be enriched with real hostnames and IPs.
    // Include entries that have a device_name OR an ip_address (or both) so that
    // MACs with a known IP but no registered name still allow IP enrichment.
    $macRegistry = [];
    $regResult = $conn->query(
        "SELECT mac_address, device_name, ip_address FROM mac_device_registry
          WHERE (device_name IS NOT NULL AND device_name != '')
             OR (ip_address  IS NOT NULL AND ip_address  != '')"
    );
    if ($regResult) {
        while ($row = $regResult->fetch_assoc()) {
            $cleanMac = strtoupper(preg_replace('/[^a-fA-F0-9]/', '', $row['mac_address'] ?? ''));
            if (strlen($cleanMac) === 12) {
                $macRegistry[$cleanMac] = $row;
            }
        }
    }

    $ports = [];
    $hubPortsCount = 0;
    $normalPortsWithCommas = 0;
    
    while ($p = $portsResult->fetch_assoc()) {
        $switchIdKey = $p['switch_id'];
        if (!isset($ports[$switchIdKey])) {
            $ports[$switchIdKey] = [];
        }
        
        $ip = $p['ip'] ?? '';
        $mac = $p['mac'] ?? '';
        $device = $p['device'] ?? '';
        $type = $p['type'] ?? 'BOŞ';
        $isHubDb = isset($p['is_hub']) ? (int)$p['is_hub'] : 0;
        $multipleConnections = $p['multiple_connections'] ?? '';
        $connectionInfo = $p['connection_info'] ?? '';
        $hubName = $p['hub_name'] ?? '';
        
        $isHub = $isHubDb;
        
        $parsedConnections = [];
        $hasConnectionInfo = false;
        
        if (!empty($connectionInfo) && $connectionInfo !== '[]' && $connectionInfo !== 'null') {
            $parsedConnections = parseConnectionInfo($connectionInfo);
            $hasConnectionInfo = !empty($parsedConnections);
        }
        
        if (!$hasConnectionInfo && !empty($multipleConnections) && $multipleConnections !== '[]' && $multipleConnections !== 'null') {
            $parsedConnections = parseConnectionInfo($multipleConnections);
            $hasConnectionInfo = !empty($parsedConnections);
        }

        // If multiple_connections contains a virtual_core* JSON object (not a real
        // hub-device array), clear it so the JS client doesn't treat it as hub data.
        // Without this, the tooltip "if (multi)" branch fires and shows
        // "Hub bilgisi mevcut değil" while blocking the correct virtual_core_reverse
        // formatted output from the "else if (connPreserved)" branch.
        if (!$hasConnectionInfo && !empty($multipleConnections)) {
            $mcDecoded = json_decode($multipleConnections, true);
            if (is_array($mcDecoded) && !isset($mcDecoded[0])) {
                // Non-array JSON object: check if it's a virtual_core marker
                $mcType = $mcDecoded['type'] ?? '';
                if ($mcType === 'virtual_core' || $mcType === 'virtual_core_reverse') {
                    $multipleConnections = '';
                }
            }
        }
        
        if (!$isHub) {
            $isHub = isHubFromData($ip, $mac, $connectionInfo);
            if (!$isHub && (strpos($ip, ',') !== false || strpos($mac, ',') !== false)) {
                $normalPortsWithCommas++;
            }
        }
        
        $ipCount = 0;
        $macCount = 0;
        
        if ($isHub) {
            $hubPortsCount++;
            // JACKPOT (VLAN 150), DRGT (VLAN 1500) and KAMERA (VLAN 80) ports routinely
            // have a Hub switch behind them with multiple MACs.  Preserve their specific
            // type so the UI shows KAMERA/JACKPOT/DRGT rather than the generic HUB label.
            if ($type !== 'HUB' && !in_array($type, ['JACKPOT', 'DRGT', 'KAMERA'])) {
                $type = 'HUB';
            }
            
            if (!empty($ip)) {
                $ipParts = preg_split('/[\r\n,;\s]+/', $ip);
                $ipParts = array_map('trim', $ipParts);
                $ipParts = array_filter($ipParts, function($item) {
                    $item = trim($item);
                    return !empty($item) && $item !== '-' && filter_var($item, FILTER_VALIDATE_IP);
                });
                $ipCount = count($ipParts);
            }
            
            if (!empty($mac)) {
                $macParts = preg_split('/[\r\n,;\s]+/', $mac);
                $macParts = array_map('trim', $macParts);
                $macParts = array_filter($macParts, function($item) {
                    $item = trim($item);
                    return !empty($item) && $item !== '-' && strlen(preg_replace('/[^a-fA-F0-9]/', '', $item)) >= 12;
                });
                $macCount = count($macParts);
            }
            
            if (!$hasConnectionInfo && ($ipCount > 0 || $macCount > 0)) {
                $parsedConnections = [];
                $maxCount = max($ipCount, $macCount, 1);
                
                for ($i = 0; $i < $maxCount; $i++) {
                    $connDevice = $device && !in_array(strtoupper($device), ['HUB', 'HUB PORT', 'BOŞ']) ? 
                                 $device . ' - Cihaz ' . ($i + 1) : 'Cihaz ' . ($i + 1);
                    
                    $connIp = isset($ipParts[$i]) ? $ipParts[$i] : '';
                    $connMac = isset($macParts[$i]) ? $macParts[$i] : '';
                    
                    if (!empty($connMac)) {
                        $cleanMac = preg_replace('/[^a-fA-F0-9]/', '', $connMac);
                        if (strlen($cleanMac) === 12) {
                            $connMac = implode(':', str_split($cleanMac, 2));
                        } else {
                            $connMac = '';
                        }
                    }
                    
                    if (!empty($connIp) && !filter_var($connIp, FILTER_VALIDATE_IP)) {
                        $connIp = '';
                    }
                    
                    $parsedConnections[] = [
                        'device' => $connDevice,
                        'ip' => $connIp,
                        'mac' => $connMac,
                        'type' => 'DEVICE'
                    ];
                }
                
                $hasConnectionInfo = true;
            } elseif ($hasConnectionInfo && $macCount > 0) {
                // parsedConnections already built from multiple_connections JSON, but
                // SNMP may have detected more MACs than are configured.  Augment the
                // list with any extra MACs so the hub popup shows all devices.
                $existingMacs = [];
                foreach ($parsedConnections as $pc) {
                    $em = strtoupper(preg_replace('/[^a-fA-F0-9]/', '', $pc['mac'] ?? ''));
                    if (strlen($em) === 12) $existingMacs[] = $em;
                }
                $nextIdx = count($parsedConnections) + 1;
                foreach (array_values($macParts) as $extraMac) {
                    $cleanExtra = strtoupper(preg_replace('/[^a-fA-F0-9]/', '', $extraMac));
                    if (strlen($cleanExtra) !== 12) continue;
                    if (in_array($cleanExtra, $existingMacs)) continue;
                    // Normalise MAC to colon-separated form
                    $normMac = implode(':', str_split($cleanExtra, 2));
                    $parsedConnections[] = [
                        'device' => 'Cihaz ' . $nextIdx,
                        'ip'     => '',
                        'mac'    => $normMac,
                        'type'   => 'DEVICE'
                    ];
                    $existingMacs[] = $cleanExtra;
                    $nextIdx++;
                }
            }
            
            if (empty($device) || in_array(strtoupper($device), ['BOŞ', 'HUB PORT', 'HUB'])) {
                $totalDevices = count($parsedConnections) > 0 ? count($parsedConnections) : max($ipCount, $macCount, 1);
                $device = $hubName ? $hubName . " ($totalDevices port)" : "$totalDevices port";
            }
            
            $isActive = true;
            
        } else {
            // NOTE: mac_device_registry read-time enrichment was intentionally removed.
            // Previously getData.php would look up ports.mac in mac_device_registry and
            // re-write $device at read time. This caused device labels (AP, TV, DEVICE…)
            // to reappear immediately after a "boşa çek" (reset) because the SNMP worker
            // re-writes ports.mac for UP ports — and the registry lookup then overrode the
            // intentionally cleared device name. Ports remain active without a device label
            // via $hasMeaningfulType (e.g. type='ETHERNET'). Device Import still works: the
            // "Portlara Uygula" action writes directly to ports.device / ports.ip in the DB.

            $hasIpOrMac = !empty($ip) || !empty($mac);
            $hasDevice = !empty($device) && $device != 'BOŞ' && !in_array(strtoupper($device), ['HUB', 'HUB PORT']);
            $hasConnection = $hasConnectionInfo;
            // Also treat "VLAN X" and known device types as active indicators
            $isVlanType = (strpos($type, 'VLAN ') === 0);
            $meaningfulTypes = ['DEVICE','SERVER','AP','KAMERA','IPTV','OTOMASYON','SANTRAL','FIBER','ETHERNET','HUB'];
            $hasMeaningfulType = in_array(strtoupper($type), $meaningfulTypes) || $isVlanType;
            
            $isActive = ($hasIpOrMac && $hasDevice) || $hasConnection || ($hasMeaningfulType && $type !== 'BOŞ' && $type !== 'EMPTY');
            
            if (!$isActive) {
                $type = 'BOŞ';
                $device = '';
                $ip = '';
                $mac = '';
                $parsedConnections = [];
            } elseif ($type == 'BOŞ' || $type == 'EMPTY') {
                $type = 'DEVICE';
            }
        }
        
        // Apply SNMP VLAN → type mapping.
        // snmp_vlan_id comes from port_status_data, which is written by both the
        // Python autosync worker (active FDB/bitmask walk) and the PHP egress walk
        // (snmp_data_api.php).  The egress bitmask includes DOWN ports, so
        // snmp_vlan_id can be > 1 for DOWN ports too.  Apply the mapping for all
        // ports (UP and DOWN) when snmp_vlan_id is non-trivial.
        // FIBER ports are excluded (they are infrastructure uplinks, not access devices).
        $vlanTypeMapPhp = [30=>'GUEST',40=>'VIP',50=>'DEVICE',70=>'AP',80=>'KAMERA',110=>'SES',120=>'OTOMASYON',130=>'IPTV',140=>'SANTRAL',150=>'JACKPOT',254=>'SERVER',1500=>'DRGT'];
        $snmpVlanId = !empty($p['snmp_vlan_id']) ? (int)$p['snmp_vlan_id'] : 0;
        if (!$isHub && $snmpVlanId > 1 && isset($vlanTypeMapPhp[$snmpVlanId])
            && $type !== 'FIBER') {
            $type = $vlanTypeMapPhp[$snmpVlanId];
        }

        // Determine whether the port is operationally DOWN.
        //
        // Two sources, used exclusively (not combined):
        //
        //   1. port_status_data.oper_status ($psdOperStatus) — Python worker's latest SNMP
        //      poll.  Only the explicit 'up' and 'down' values are treated as authoritative.
        //      'unknown' means the worker could not determine status (e.g. ifOperStatus
        //      returned a value outside the known set) and is treated the same as NULL so
        //      that the ports.oper_status fallback can decide.
        //      Rule:
        //        'up'    → UP (not down)
        //        'down'  → DOWN
        //        other   → fall through to ports.oper_status (see case 2)
        //
        //   2. ports.oper_status ($portsOperStatus) — fallback when psd row is absent or
        //      psd_oper_status is 'unknown'/'disabled' (i.e. not conclusive).
        //      Only 'down' / 'lowerLayerDown' are treated as DOWN; anything else is UP.
        //
        // NOTE: CBS350 lowerLayerDown ports are stored as 'down' (not 'unknown') in
        // port_status_data since the lowerLayerDown→DOWN mapping in polling_engine.py,
        // so they correctly hit the 'down' branch above.
        $psdOperStatus   = $p['psd_oper_status'] ?? null;
        $portsOperStatus = $p['oper_status'] ?? 'unknown';
        if ($psdOperStatus === 'up') {
            $isDown = false;
        } elseif ($psdOperStatus === 'down' || $psdOperStatus === 'disabled') {
            // 'disabled' means the port is administratively shut down — treat as DOWN
            // so it shows with the red DOWN indicator in the UI.
            $isDown = true;
        } else {
            // psd_oper_status is NULL, 'unknown', or any other unexpected value
            // → fall back to the legacy ports.oper_status column.
            $isDown = ($portsOperStatus === 'down' || $portsOperStatus === 'lowerLayerDown');
        }

        // The SNMP port alias (ifAlias – admin-configured description on the switch port)
        // is sent in the JSON so it can be shown in the port detail modal (Alias field).
        // It is intentionally NOT used to populate the card-level device label; doing so
        // caused switch-configured names (AP, TV, DEVICE …) to reappear on every port
        // after a "boşa çek" (reset), making the reset look ineffective.
        $snmpPortAlias = isset($p['snmp_port_alias']) ? trim($p['snmp_port_alias']) : '';

        // Enrich hub device entries with real hostnames from mac_device_registry.
        // When the SNMP worker only knows the MAC address it stores a placeholder
        // ("Cihaz X" or empty).  If the device has been imported via Device Import
        // (or auto-registered), replace the placeholder with the real hostname and
        // fill in the IP if it was missing.
        if ($hasConnectionInfo && !empty($parsedConnections) && !empty($macRegistry)) {
            foreach ($parsedConnections as &$pc) {
                $pcMac = strtoupper(preg_replace('/[^a-fA-F0-9]/', '', $pc['mac'] ?? ''));
                if (strlen($pcMac) !== 12 || !isset($macRegistry[$pcMac])) {
                    continue;
                }
                $regEntry = $macRegistry[$pcMac];
                $pcDevice = trim($pc['device'] ?? '');
                $isGenericDevice = $pcDevice === ''
                    || preg_match('/^Cihaz\s*\d*$/i', $pcDevice)
                    || preg_match('/ - Cihaz\s+\d+$/i', $pcDevice);
                if ($isGenericDevice && !empty($regEntry['device_name'])) {
                    $pc['device'] = $regEntry['device_name'];
                }
                // Fill IP from registry when the connection entry has none
                if (empty($pc['ip']) && !empty($regEntry['ip_address'])) {
                    $pc['ip'] = $regEntry['ip_address'];
                }
            }
            unset($pc); // break reference
        }

        // Enrich single-device non-hub ports: if the port has a MAC but no IP, look up
        // the IP from mac_device_registry (same source used for hub port enrichment above).
        if (!$isHub && empty($ip) && !empty($mac) && !empty($macRegistry)) {
            $cleanMac = strtoupper(preg_replace('/[^a-fA-F0-9]/', '', $mac));
            if (strlen($cleanMac) === 12 && isset($macRegistry[$cleanMac])) {
                $regIp = $macRegistry[$cleanMac]['ip_address'] ?? '';
                if (!empty($regIp)) {
                    $ip = $regIp;
                }
            }
        }

        // Propagate port-level IP back into single-device parsedConnections entry.
        // When connection_info stored the device before mac_device_registry had an IP,
        // parsedConnections[0]['ip'] is empty even though $ip is now populated (e.g. via
        // the MAC-based registry lookup above).  Reflect the IP into parsedConnections so
        // the detail modal's "Mevcut Bağlantı" section shows the correct IP.
        if (!$isHub && !empty($parsedConnections) && count($parsedConnections) === 1
            && empty($parsedConnections[0]['ip']) && !empty($ip)) {
            $parsedConnections[0]['ip'] = $ip;
        }

        // Rebuild $multipleConnections from enriched parsedConnections so that
        // the JS hub modal and tooltip both receive real hostnames.
        if ($hasConnectionInfo && !empty($parsedConnections)) {
            $multipleConnections = json_encode($parsedConnections, JSON_UNESCAPED_UNICODE);
        }

        $portDataOut = [
            "port" => (int)$p['port_no'],
            "type" => $type,
            "device" => $device,
            "ip" => $ip,
            "mac" => $mac,
            "is_active" => $isActive,
            "is_down" => $isDown,
            "is_hub" => $isHub,
            "ip_count" => $ipCount,
            "mac_count" => $macCount,
            "multiple_connections" => $multipleConnections,
            "connection_info" => $hasConnectionInfo ? json_encode($parsedConnections, JSON_UNESCAPED_UNICODE) : '',
            "device_count" => count($parsedConnections),
            "has_connection" => $hasConnectionInfo,
            "hub_name" => $hubName,
            "connections" => $parsedConnections,
            "connected_panel_id" => $p['connected_panel_id'],
            "connected_panel_port" => $p['connected_panel_port'],
            "connected_panel_letter" => $p['connected_panel_letter'],
            "connected_panel_rack" => $p['connected_panel_rack'],
            "panel_type" => $p['panel_type'],
            "connection_info_preserved" => $p['connection_info_preserved'],
            "snmp_vlan_id" => isset($p['snmp_vlan_id']) ? (int)$p['snmp_vlan_id'] : null,
            "snmp_vlan_name" => $p['snmp_vlan_name'] ?? null,
            "snmp_port_alias" => $snmpPortAlias !== '' ? $snmpPortAlias : null,
            "is_uplink" => !empty($p['is_uplink']),
            "snmp_poe_detecting" => isset($p['snmp_poe_detecting']) ? (int)$p['snmp_poe_detecting'] : null,
            "snmp_poe_power_mw"  => isset($p['snmp_poe_power_mw'])  ? (int)$p['snmp_poe_power_mw']  : null,
            // Fallback core switch connection info from snmp_core_ports.
            // Used by the frontend when connection_info_preserved has no valid JSON
            // (e.g. only raw LLDP port description "Te1/1/2") so the tooltip can
            // still show the correct CORESW connection point.
            "core_connection_info" => (!empty($p['core_switch_name_fallback'])
                && (empty($p['connection_info_preserved'])
                    || ltrim($p['connection_info_preserved'])[0] !== '{'))
                ? $p['core_switch_name_fallback']
                : null,
            // Reverse fallback for core switch ports: supplies a synthetic
            // virtual_core_reverse JSON when connection_info_preserved is missing/non-JSON.
            // Built from the snmp_core_ports reverse lookup above.
            // Applies to ALL core switches (real and virtual), because real core switches
            // read this from the DOM's data-connection attribute in the port detail modal.
            "core_reverse_fallback" => (function() use ($p, &$coreSwPortToEdge) {
                if (!(int)($p['sw_is_core'] ?? 0)) return null;
                $ci = trim($p['connection_info_preserved'] ?? '');
                if ($ci !== '' && $ci[0] === '{') return null; // already has valid JSON
                $key = ($p['sw_name'] ?? '') . ':' . $p['port_no'];
                if (!isset($coreSwPortToEdge[$key])) return null;
                $info = $coreSwPortToEdge[$key];
                return json_encode([
                    'type'             => 'virtual_core_reverse',
                    'edge_switch_name' => $info['edge_sw_name'],
                    'edge_port_no'     => $info['edge_port_no'],
                ], JSON_UNESCAPED_UNICODE);
            })(),
        ];
        
        if (isset($p['rack_port'])) {
            $portDataOut["rack_port"] = (int)$p['rack_port'];
        }
        
        $ports[$switchIdKey][] = $portDataOut;
    }
    
    // Topology creation
    $topologyData = [];
    
    foreach ($ports as $sid => $switchPorts) {
        foreach ($switchPorts as $port) {
            if ($port['connected_panel_id']) {
                $topologyData[] = [
                    'type' => 'switch_to_panel',
                    'source' => [
                        'type' => 'switch',
                        'id' => $sid,
                        'port' => $port['port']
                    ],
                    'target' => [
                        'type' => 'panel',
                        'panel_type' => $port['panel_type'],
                        'id' => $port['connected_panel_id'],
                        'port' => $port['connected_panel_port'],
                        'letter' => $port['connected_panel_letter'],
                        'rack' => $port['connected_panel_rack']
                    ]
                ];
            }
        }
    }
    
    foreach ($patchPorts as $panelId => $panelPortsList) {
        foreach ($panelPortsList as $port) {
            if ($port['connected_switch_id']) {
                $topologyData[] = [
                    'type' => 'panel_to_switch',
                    'source' => [
                        'type' => 'patch_panel',
                        'id' => $panelId,
                        'port' => $port['port_number'],
                        'letter' => $port['panel_letter']
                    ],
                    'target' => [
                        'type' => 'switch',
                        'id' => $port['connected_switch_id'],
                        'port' => $port['connected_switch_port'],
                        'name' => $port['connected_switch_name']
                    ]
                ];
            }
        }
    }
    
    foreach ($fiberPorts as $panelId => $fiberPortsList) {
        foreach ($fiberPortsList as $port) {
            if ($port['connected_switch_id']) {
                $topologyData[] = [
                    'type' => 'fiber_to_switch',
                    'source' => [
                        'type' => 'fiber_panel',
                        'id' => $panelId,
                        'port' => $port['port_number'],
                        'letter' => $port['panel_letter']
                    ],
                    'target' => [
                        'type' => 'switch',
                        'id' => $port['connected_switch_id'],
                        'port' => $port['connected_switch_port'],
                        'name' => $port['connected_switch_name']
                    ],
                    'is_jump_point' => (bool)$port['is_jump_point'],
                    'jump_path' => $port['jump_path']
                ];
            }
            
            if ($port['connected_fiber_panel_id']) {
                $topologyData[] = [
                    'type' => 'fiber_to_fiber',
                    'source' => [
                        'type' => 'fiber_panel',
                        'id' => $panelId,
                        'port' => $port['port_number'],
                        'letter' => $port['panel_letter']
                    ],
                    'target' => [
                        'type' => 'fiber_panel',
                        'id' => $port['connected_fiber_panel_id'],
                        'port' => $port['connected_fiber_panel_port'],
                        'letter' => $port['connected_fiber_panel_letter']
                    ],
                    'is_jump_point' => (bool)$port['is_jump_point']
                ];
            }
        }
    }
    
    // Stats
    $stats = [
        'total_switches' => count($switches),
        'total_racks' => count($racks),
        'active_ports' => 0,
        'total_ports' => 0,
        'hub_ports' => $hubPortsCount,
        'normal_ports_with_commas' => $normalPortsWithCommas,
        'total_patch_panels' => count($patchPanels),
        'total_fiber_panels' => count($fiberPanels),
        'total_patch_ports' => array_sum(array_map('count', $patchPorts)),
        'active_patch_ports' => 0,
        'total_fiber_ports' => array_sum(array_map('count', $fiberPorts))
    ];
    
    foreach ($ports as $switchPorts) {
        $stats['total_ports'] += count($switchPorts);
        foreach ($switchPorts as $port) {
            if ($port['is_active']) $stats['active_ports']++;
        }
    }
    
    foreach ($patchPorts as $panelPorts) {
        foreach ($panelPorts as $port) {
            if ($port['status'] === 'active') $stats['active_patch_ports']++;
        }
    }

    // Rack devices (server / hub_sw) – tablo yoksa oluştur ve boş dizi döndür
    $conn->query("CREATE TABLE IF NOT EXISTS rack_devices (
        id             INT AUTO_INCREMENT PRIMARY KEY,
        rack_id        INT         NOT NULL,
        device_type    ENUM('server','hub_sw') NOT NULL,
        name           VARCHAR(120) NOT NULL,
        ports          SMALLINT    NOT NULL DEFAULT 0,
        fiber_ports    SMALLINT    NOT NULL DEFAULT 0,
        unit_size      TINYINT     NOT NULL DEFAULT 1,
        position_in_rack TINYINT   DEFAULT NULL,
        notes          TEXT        DEFAULT NULL,
        created_at     DATETIME    DEFAULT NOW(),
        updated_at     DATETIME    DEFAULT NOW() ON UPDATE NOW(),
        INDEX idx_rack (rack_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    // Add fiber_ports column if it was missing from an older schema
    $conn->query("IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='rack_devices' AND COLUMN_NAME='fiber_ports') BEGIN ALTER TABLE rack_devices ADD fiber_ports SMALLINT NOT NULL DEFAULT 0 END");
    $rackDevices = [];
    $rdRes = $conn->query("SELECT * FROM rack_devices ORDER BY rack_id, CASE WHEN position_in_rack IS NULL THEN 1 ELSE 0 END, position_in_rack, id");
    if ($rdRes) {
        while ($rd = $rdRes->fetch_assoc()) {
            $rd['id']          = (int)$rd['id'];
            $rd['rack_id']     = (int)$rd['rack_id'];
            $rd['ports']       = (int)$rd['ports'];
            $rd['fiber_ports'] = (int)($rd['fiber_ports'] ?? 0);
            $rd['unit_size']   = (int)$rd['unit_size'];
            $rd['position_in_rack'] = $rd['position_in_rack'] !== null ? (int)$rd['position_in_rack'] : null;
            $rackDevices[] = $rd;
        }
    }

    // Hub SW port direct connections
    $conn->query("CREATE TABLE IF NOT EXISTS hub_sw_port_connections (
        id             INT AUTO_INCREMENT PRIMARY KEY,
        rack_device_id INT NOT NULL,
        port_number    SMALLINT NOT NULL,
        conn_type      VARCHAR(30) NOT NULL DEFAULT 'device',
        device_name    VARCHAR(255) DEFAULT NULL,
        switch_id      INT DEFAULT NULL,
        switch_port    INT DEFAULT NULL,
        notes          TEXT DEFAULT NULL,
        updated_at     DATETIME DEFAULT NOW() ON UPDATE NOW(),
        UNIQUE KEY uk_rdport (rack_device_id, port_number),
        INDEX idx_rd (rack_device_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    $hubSwPortConnections = [];
    $hscRes = $conn->query("SELECT * FROM hub_sw_port_connections ORDER BY rack_device_id, port_number");

    // Migration: ensure CHK_alarms_acknowledgment_type constraint includes 'device_registered'.
    // The live database may have an older constraint that was created before this value was added.
    $conn->query("
        IF OBJECT_ID(N'alarms', 'U') IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM sys.check_constraints
                WHERE name = 'CHK_alarms_acknowledgment_type'
                  AND OBJECT_DEFINITION(object_id) NOT LIKE '%device_registered%'
            )
        BEGIN
            ALTER TABLE alarms DROP CONSTRAINT CHK_alarms_acknowledgment_type;
            ALTER TABLE alarms ADD CONSTRAINT CHK_alarms_acknowledgment_type
                CHECK (acknowledgment_type IN ('known_change','silenced','resolved','false_alarm','mac_moved','device_registered',''));
        END
    ");
    if ($hscRes) {
        while ($hsc = $hscRes->fetch_assoc()) {
            $hsc['id']             = (int)$hsc['id'];
            $hsc['rack_device_id'] = (int)$hsc['rack_device_id'];
            $hsc['port_number']    = (int)$hsc['port_number'];
            if ($hsc['switch_id'] !== null)   $hsc['switch_id']   = (int)$hsc['switch_id'];
            if ($hsc['switch_port'] !== null) $hsc['switch_port'] = (int)$hsc['switch_port'];
            $hubSwPortConnections[] = $hsc;
        }
    }

    echo json_encode([
        "success" => true,
        "racks" => $racks,
        "switches" => $switches,
        "ports" => $ports,
        "patch_panels" => $patchPanels,
        "patch_ports" => $patchPorts,
        "fiber_panels" => $fiberPanels,
        "fiber_ports" => $fiberPorts,
        "rack_devices" => $rackDevices,
        "hub_sw_port_connections" => $hubSwPortConnections,
        "topology" => $topologyData,
        "stats" => $stats,
        "debug_info" => [
            "total_ports_processed" => array_sum(array_map('count', $ports)),
            "hub_ports_count" => $hubPortsCount,
            "normal_ports_with_commas" => $normalPortsWithCommas
        ]
    ], JSON_UNESCAPED_UNICODE);
    
} catch (Exception $e) {
    echo json_encode([
        "success" => false,
        "error" => $e->getMessage(),
        "racks" => [],
        "switches" => [],
        "ports" => [],
        "patch_panels" => [],
        "patch_ports" => [],
        "fiber_panels" => [],
        "fiber_ports" => [],
        "rack_devices" => [],
        "hub_sw_port_connections" => [],
        "topology" => []
    ]);
}

$conn->close();
?>