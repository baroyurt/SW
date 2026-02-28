<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

include "db.php";

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
    
    // Switches
    $switchQuery = "
        SELECT s.*, r.name as rack_name, r.location as rack_location
        FROM switches s 
        LEFT JOIN racks r ON s.rack_id = r.id
        ORDER BY s.name
    ";
    $switchesResult = $conn->query($switchQuery);
    if (!$switchesResult) {
        throw new Exception("Switch sorgusu hatası: " . $conn->error);
    }
    $switches = $switchesResult->fetch_all(MYSQLI_ASSOC);
    
    // Patch Panels
    $patchQuery = "
        SELECT pp.*, r.name as rack_name, r.location,
               COUNT(ppo.id) as total_ports_created,
               SUM(CASE WHEN ppo.status = 'active' THEN 1 ELSE 0 END) as active_ports
        FROM patch_panels pp
        LEFT JOIN racks r ON pp.rack_id = r.id
        LEFT JOIN patch_ports ppo ON pp.id = ppo.panel_id
        GROUP BY pp.id
        ORDER BY r.name, pp.panel_letter
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
        ORDER BY r.name, fp.panel_letter
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
            psd.vlan_name as snmp_vlan_name
        FROM ports p
        LEFT JOIN patch_panels pp 
               ON p.connected_panel_id = pp.id 
              AND p.connected_panel_id IN ($validPanelList)
        LEFT JOIN racks pp_rack 
               ON pp.rack_id = pp_rack.id
        LEFT JOIN switches s ON p.switch_id = s.id
        LEFT JOIN snmp_devices sd ON (s.name = sd.name OR s.ip = sd.ip_address)
        LEFT JOIN (
            SELECT device_id, port_number, vlan_id, vlan_name, oper_status AS psd_oper_status
            FROM port_status_data
            WHERE id IN (
                SELECT MAX(id)
                FROM port_status_data
                GROUP BY device_id, port_number
            )
        ) psd ON sd.id = psd.device_id AND p.port_no = psd.port_number
        WHERE (COALESCE(sd.total_ports, s.ports, 0) = 0 OR p.port_no <= COALESCE(sd.total_ports, s.ports, 0))
        ORDER BY p.switch_id, p.port_no
    ";
    
    $portsResult = $conn->query($portQuery);
    if (!$portsResult) {
        throw new Exception("Port sorgusu hatası: " . $conn->error);
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
            if ($type !== 'HUB') {
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
            }
            
            if (empty($device) || in_array(strtoupper($device), ['BOŞ', 'HUB PORT', 'HUB'])) {
                $totalDevices = count($parsedConnections) > 0 ? count($parsedConnections) : max($ipCount, $macCount, 1);
                $device = $hubName ? $hubName . " ($totalDevices cihaz)" : "Hub Port ($totalDevices cihaz)";
            }
            
            $isActive = true;
            
        } else {
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
        
        // Apply SNMP VLAN → type mapping for UP ports.
        // snmp_vlan_id is joined from port_status_data using MAX(id) per port,
        // so it always reflects the latest SNMP poll result.
        // This overrides stale ports.type values without waiting for the next autosync cycle.
        // FIBER ports are excluded (they are infrastructure uplinks, not access devices).
        $vlanTypeMapPhp = [30=>'SANTRAL',50=>'DEVICE',70=>'AP',80=>'KAMERA',120=>'OTOMASYON',130=>'IPTV',140=>'SANTRAL',254=>'DEVICE'];
        $snmpVlanId = !empty($p['snmp_vlan_id']) ? (int)$p['snmp_vlan_id'] : 0;
        // snmp_vlan_id > 1 already proves port is UP (DOWN ports are absent from VLAN untagged mask walk)
        if (!$isHub && $snmpVlanId > 1 && isset($vlanTypeMapPhp[$snmpVlanId])
            && $type !== 'FIBER') {
            $type = $vlanTypeMapPhp[$snmpVlanId];
        }

        // Prefer oper_status from port_status_data (Python worker's latest poll)
        // over ports.oper_status (autosync updates this too, but psd is more granular).
        $operStatus = $p['psd_oper_status'] ?? $p['oper_status'] ?? 'unknown';
        $isDown = ($operStatus === 'down');
        
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
            "snmp_vlan_name" => $p['snmp_vlan_name'] ?? null
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
    
    echo json_encode([
        "success" => true,
        "racks" => $racks,
        "switches" => $switches,
        "ports" => $ports,
        "patch_panels" => $patchPanels,
        "patch_ports" => $patchPorts,
        "fiber_panels" => $fiberPanels,
        "fiber_ports" => $fiberPorts,
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
        "topology" => []
    ]);
}

$conn->close();
?>