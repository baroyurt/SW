<?php
/**
 * CBS350-24FP SNMP - TÜM SNMP VERİLERİ (PORT BAZINDA 50+ PARAMETRE)
 * SW35-BALO (EDGE-SW35)
 */

error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('max_execution_time', 120);

while (ob_get_level()) ob_end_clean();
ob_start();

if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
    header('Content-Type: application/json; charset=utf-8');
}

header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

$switch_config = [
    'host' => isset($_REQUEST['host']) ? preg_replace('/[^0-9a-fA-F.:]/', '', $_REQUEST['host']) : '172.18.1.214',
    'username' => 'snmpuser',
    'engine_id' => '0102030405060708',
    'auth_protocol' => 'SHA',
    'priv_protocol' => 'AES',
    'auth_password' => 'AuthPass123',
    'priv_password' => 'PrivPass123'
];

function parseSnmpValue($value) {
    if (empty($value) || $value === false) return '';
    $value = trim($value);
    $value = preg_replace('/^(INTEGER|STRING|Hex-STRING|IpAddress|Counter32|Counter64|Gauge32|TimeTicks|BITS|OID):\s*/i', '', $value);
    return trim($value, '"\'');
}

function formatMac($mac) {
    if (empty($mac)) return '';
    if (preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $mac)) return strtoupper($mac);
    $mac = preg_replace('/[^0-9A-Fa-f]/', '', $mac);
    if (strlen($mac) == 12) return strtoupper(implode(':', str_split($mac, 2)));
    if (strlen($mac) == 6) return strtoupper(implode(':', str_split(bin2hex($mac), 2)));
    return '';
}

function formatBytes($b) { if (!$b) return '0 B'; $b = intval($b); $u = ['B','KB','MB','GB','TB']; $i=0; while($b>=1024 && $i<4) { $b/=1024; $i++; } return round($b,2).' '.$u[$i]; }
function formatUptime($t) { if (!$t) return 'N/A'; $s = floor(intval($t)/100); return floor($s/86400).'g '.floor(($s%86400)/3600).'s '.floor(($s%3600)/60).'d'; }
function formatSpeed($s) { if (!$s) return 'N/A'; $s=intval($s); if($s>=1e9) return round($s/1e9,1).' Gbps'; if($s>=1e6) return round($s/1e6,1).' Mbps'; if($s>=1e3) return round($s/1e3,1).' Kbps'; return $s.' bps'; }

function stpState($s) { return [1=>'disabled',2=>'blocking',3=>'listening',4=>'learning',5=>'forwarding'][$s]??'unknown'; }
function stpRole($r) { return [1=>'disabled',2=>'alternate',3=>'backup',4=>'root',5=>'designated'][$r]??'unknown'; }
function duplex($d) { return [1=>'half',2=>'full',3=>'auto'][$d]??'unknown'; }
function poeClass($c) { return [0=>'Class0(15.4W)',1=>'Class1(4W)',2=>'Class2(7W)',3=>'Class3(15.4W)',4=>'Class4(30W)'][$c]??"Class$c"; }
function ifType($t) { $types=[6=>'ethernet',24=>'softwareLoopback',28=>'slip',53=>'propVirtual',117=>'gigabitEthernet',135=>'l2vlan',136=>'ds3',161=>'tunnel',209=>'vlan']; return $types[$t]??$t; }

function isAjax() {
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isAjax()) {
    try {
        $input = json_decode(file_get_contents('php://input'), true) ?: $_POST;
        
        if (isset($input['auth_password'])) $switch_config['auth_password'] = $input['auth_password'];
        if (isset($input['priv_password'])) $switch_config['priv_password'] = $input['priv_password'];

        // Load all SNMP credentials from snmp_devices DB table.
        // This mirrors snmp_port_detail.php / snmp_data_api.php so credentials are
        // always consistent with what the Python worker uses.
        // When no engine_id is stored (C9200L uses auto-discovery), keep '' so PHP
        // SNMP performs the standard SNMPv3 engine discovery handshake.
        if (file_exists(__DIR__ . '/db.php')) {
            require_once __DIR__ . '/db.php';
            $credStmt = $conn->prepare("
                SELECT snmp_version, snmp_community,
                       snmp_v3_username, snmp_v3_auth_protocol,
                       snmp_v3_auth_password, snmp_v3_priv_protocol,
                       snmp_v3_priv_password, snmp_engine_id
                FROM snmp_devices WHERE ip_address = ? LIMIT 1
            ");
            if ($credStmt && $credStmt->bind_param('s', $switch_config['host']) && $credStmt->execute()) {
                $credRow = $credStmt->get_result()->fetch_assoc();
                if ($credRow) {
                    if (!empty($credRow['snmp_v3_username']))      $switch_config['username']      = $credRow['snmp_v3_username'];
                    if (!empty($credRow['snmp_v3_auth_protocol'])) $switch_config['auth_protocol'] = $credRow['snmp_v3_auth_protocol'];
                    if (!empty($credRow['snmp_v3_priv_protocol'])) $switch_config['priv_protocol'] = $credRow['snmp_v3_priv_protocol'];
                    // Only use DB passwords when user hasn't overridden them via POST
                    if (!isset($input['auth_password']) && !empty($credRow['snmp_v3_auth_password']))
                        $switch_config['auth_password'] = $credRow['snmp_v3_auth_password'];
                    if (!isset($input['priv_password']) && !empty($credRow['snmp_v3_priv_password']))
                        $switch_config['priv_password'] = $credRow['snmp_v3_priv_password'];
                    // engine_id: '' means auto-discover (correct for C9200L)
                    $switch_config['engine_id'] = $credRow['snmp_engine_id'] ?? '';
                }
            }
        }

        while (ob_get_level()) ob_end_clean();
        
        if ($input['action'] === 'get_all_data') {
            getAllSwitchData($switch_config);
        } else {
            echo json_encode(['success' => false, 'error' => 'Geçersiz action']);
        }
        exit;
    } catch (Exception $e) {
        while (ob_get_level()) ob_end_clean();
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        exit;
    }
}

/**
 * Fallback: build response from port_status_data when PHP SNMP is unavailable.
 * The Python worker keeps this table up-to-date, so the data is still live.
 */
function getDataFromDB($host, &$result) {
    global $conn;

    // Find device in snmp_devices
    $stmt = $conn->prepare("SELECT * FROM snmp_devices WHERE ip_address = ? LIMIT 1");
    if (!$stmt || !$stmt->bind_param('s', $host) || !$stmt->execute()) {
        $result['error'] = 'Veritabanında bu IP için cihaz bulunamadı';
        echo json_encode($result);
        return;
    }
    $dev = $stmt->get_result()->fetch_assoc();
    if (!$dev) {
        $result['error'] = "Bu IP ($host) veritabanında kayıtlı değil";
        echo json_encode($result);
        return;
    }

    // Latest device polling info
    $dpStmt = $conn->prepare("SELECT * FROM device_polling_data WHERE device_id = ? ORDER BY poll_timestamp DESC LIMIT 1");
    $dpStmt->bind_param('i', $dev['id']);
    $dpStmt->execute();
    $dp = $dpStmt->get_result()->fetch_assoc();

    $result['system'] = [
        'name'       => $dev['name'],
        'descr'      => $dp['system_description'] ?? $dev['model'] ?? '',
        'uptime_text'=> '-',
        'location'   => '',
        'contact'    => '',
    ];
    $result['chassis'] = ['serial'=>'','mac'=>'','model'=>$dev['model']??'','version'=>'','firmware'=>''];
    $result['data_source'] = 'db';  // flag for JS to show notice

    // Get latest port data
    $portStmt = $conn->prepare("
        SELECT psd.*
        FROM port_status_data psd
        INNER JOIN (
            SELECT port_number, MAX(id) AS max_id FROM port_status_data WHERE device_id = ? GROUP BY port_number
        ) latest ON psd.id = latest.max_id
        ORDER BY psd.port_number ASC
    ");
    $portStmt->bind_param('i', $dev['id']);
    $portStmt->execute();
    $portRows = $portStmt->get_result()->fetch_all(MYSQLI_ASSOC);

    $totalPorts  = max($dev['total_ports'] ?? 0, count($portRows));
    $poeMaxPort  = ($totalPorts >= 48) ? 48 : 24;
    $active = $down = $poeActive = $sfpActive = 0;

    foreach ($portRows as $p) {
        $portNum  = intval($p['port_number']);
        $portType = $portNum <= $poeMaxPort ? 'PoE' : 'SFP';
        $isActive = ($p['oper_status'] === 'up');
        $isDown   = ($p['oper_status'] === 'down');

        if ($isActive) { $active++; if ($portType==='PoE') $poeActive++; else $sfpActive++; }
        if ($isDown)   $down++;

        // Speed
        $speed = intval($p['port_speed'] ?? 0);
        $speedText = $speed > 0 ? formatSpeed($speed) : 'N/A';

        // MAC
        $mac = '';
        if (!empty($p['mac_address'])) $mac = strtoupper($p['mac_address']);
        elseif (!empty($p['mac_addresses'])) {
            $macs = json_decode($p['mac_addresses'], true);
            if (is_array($macs) && !empty($macs)) $mac = strtoupper($macs[0]);
        }

        $result['ports'][$portNum] = [
            'port'       => $portNum,
            'type'       => $portType,
            'if_index'   => $portNum,
            'if_descr'   => $p['port_name']  ?? "GE$portNum",
            'if_name'    => $p['port_name']  ?? "GE$portNum",
            'if_alias'   => $p['port_alias'] ?? '',
            'admin'      => $p['admin_status'] === 'up' ? 1 : 2,
            'admin_text' => $p['admin_status'] ?? 'unknown',
            'oper'       => $isActive ? 1 : 2,
            'oper_text'  => $p['oper_status'] ?? 'unknown',
            'speed'      => $speedText,
            'mtu'        => intval($p['port_mtu'] ?? 0),
            'mac'        => $mac,
            'vlan'       => intval($p['vlan_id'] ?? 1),
            'is_active'  => $isActive,
            // Traffic counters (from DB if available)
            'in_octets'   => intval($p['in_octets']   ?? 0),
            'out_octets'  => intval($p['out_octets']  ?? 0),
            'in_errors'   => intval($p['in_errors']   ?? 0),
            'out_errors'  => intval($p['out_errors']  ?? 0),
            'in_discards' => intval($p['in_discards'] ?? 0),
            'out_discards'=> intval($p['out_discards']?? 0),
            'in_bytes_text' => formatBytes(intval($p['in_octets']  ?? 0)),
            'out_bytes_text'=> formatBytes(intval($p['out_octets'] ?? 0)),
            // PoE placeholder
            'poe_enabled' => false, 'poe_class_text'=>'', 'poe_priority'=>'',
        ];
    }

    $result['stats'] = [
        'total_ports'    => $totalPorts,
        'poe_ports'      => $poeMaxPort,
        'sfp_ports'      => $totalPorts - $poeMaxPort,
        'active_ports'   => $active,
        'active_poe'     => $poeActive,
        'active_sfp'     => $sfpActive,
        'down_ports'     => $down,
        'active_percent' => $totalPorts > 0 ? round($active / $totalPorts * 100, 1) : 0,
        'active_list'    => array_keys(array_filter($result['ports'], fn($p) => $p['is_active'])),
        'total_mac'      => 0,
        'total_vlans'    => 0,
        'total_lldp'     => 0,
    ];

    $result['success'] = true;
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_IGNORE);
}

function getAllSwitchData($config) {
    $result = [
        'success' => false,
        'system' => [],
        'chassis' => [],
        'environment' => [],
        'vlans' => [],
        'ports' => [],
        'stats' => [],
        'mac_table' => [],
        'arp_table' => [],
        'lldp' => [],
        'cdp' => [],
        'stp' => [],
        'port_channels' => [],
        'poe' => [],
        'logs' => [],
        'error' => null
    ];
    
    if (!extension_loaded('snmp')) {
        // PHP SNMP extension not available (common on XAMPP without extra config).
        // Fall back to data collected by the Python worker stored in port_status_data.
        if (file_exists(__DIR__ . '/db.php')) {
            require_once __DIR__ . '/db.php';
            getDataFromDB($config['host'], $result);
        } else {
            $result['error'] = 'SNMP extension yüklü değil ve veritabanı bağlantısı kurulamadı';
            echo json_encode($result);
        }
        exit;
    }
    
    try {
        $snmp = new SNMP(SNMP::VERSION_3, $config['host'], $config['username']);
        $snmp->setSecurity('authPriv', $config['auth_protocol'], $config['auth_password'], 
                          $config['priv_protocol'], $config['priv_password'], $config['engine_id'], '');
        $snmp->valueretrieval = SNMP_VALUE_PLAIN;
        $snmp->quick_print = true;
        $snmp->oid_increasing_check = false;  // CBS350 may return non-monotonic OIDs in walks
        $snmp->timeout = 3000000;
        $snmp->retries = 2;
        
        // ==================== SİSTEM BİLGİLERİ ====================
        $result['system'] = [
            'name' => parseSnmpValue(@$snmp->get('1.3.6.1.2.1.1.5.0')),
            'descr' => parseSnmpValue(@$snmp->get('1.3.6.1.2.1.1.1.0')),
            'uptime' => @$snmp->get('1.3.6.1.2.1.1.3.0'),
            'uptime_text' => formatUptime(@$snmp->get('1.3.6.1.2.1.1.3.0')),
            'location' => parseSnmpValue(@$snmp->get('1.3.6.1.2.1.1.6.0')),
            'contact' => parseSnmpValue(@$snmp->get('1.3.6.1.2.1.1.4.0')),
            'services' => @$snmp->get('1.3.6.1.2.1.1.7.0'),
            'object_id' => @$snmp->get('1.3.6.1.2.1.1.2.0')
        ];
        
        // ==================== CHASSIS BİLGİLERİ ====================
        $result['chassis'] = [
            'serial' => parseSnmpValue(@$snmp->get('1.3.6.1.4.1.9.9.276.1.1.1.2.1.2.1')),
            'mac' => formatMac(@$snmp->get('1.3.6.1.2.1.2.2.1.6.1')),
            'model' => parseSnmpValue(@$snmp->get('.1.3.6.1.4.1.9.9.276.1.1.1.2.1.3.1')),
            'version' => parseSnmpValue(@$snmp->get('1.3.6.1.4.1.9.9.276.1.1.1.1.1.2.1')),
            'firmware' => parseSnmpValue(@$snmp->get('1.3.6.1.4.1.9.9.276.1.1.1.1.1.3.1'))
        ];
        
        // ==================== ÇEVRE BİLGİLERİ ====================
        $result['environment'] = [
            'temp' => @$snmp->get('1.3.6.1.4.1.9.9.13.1.3.1.3.1'),
            'fan_status' => @$snmp->get('1.3.6.1.4.1.9.9.13.1.4.1.3.1'),
            'power_supply' => @$snmp->get('1.3.6.1.4.1.9.9.13.1.5.1.3.1'),
            'cpu_usage' => @$snmp->get('1.3.6.1.4.1.9.2.1.56.0'),
            'memory_usage' => @$snmp->get('1.3.6.1.4.1.9.2.1.58.0')
        ];
        
        // ==================== TÜM VLAN'LAR ====================
        $vlan_names = @$snmp->walk('1.3.6.1.2.1.17.7.1.4.2.1.5');
        $vlan_egress = @$snmp->walk('1.3.6.1.2.1.17.7.1.4.2.1.4');
        $vlan_map = [];
        
        if ($vlan_egress && is_array($vlan_egress)) {
            foreach ($vlan_egress as $oid => $mask) {
                if (preg_match('/\.(\d+)\.(\d+)$/', $oid, $m)) {
                    $vlan_id = (int)$m[2];
                    $vlan_name = '';
                    if ($vlan_names && isset($vlan_names["1.3.6.1.2.1.17.7.1.4.2.1.5.0.$vlan_id"])) {
                        $vlan_name = parseSnmpValue($vlan_names["1.3.6.1.2.1.17.7.1.4.2.1.5.0.$vlan_id"]);
                    }
                    
                    $member_ports = [];
                    $mask_len = strlen($mask);
                    for ($port = 1; $port <= 28; $port++) {
                        $byte_pos = floor(($port - 1) / 8);
                        $bit_pos = 7 - (($port - 1) % 8);
                        if ($byte_pos < $mask_len && ((ord($mask[$byte_pos]) >> $bit_pos) & 1)) {
                            $member_ports[] = $port;
                        }
                    }
                    
                    $vlan_map[$vlan_id] = [
                        'id' => $vlan_id,
                        'name' => $vlan_name,
                        'member_ports' => $member_ports,
                        'member_count' => count($member_ports)
                    ];
                }
            }
        }
        $result['vlans'] = $vlan_map;
        
        // ==================== MAC ADRES TABLOSU ====================
        $mac_addrs = @$snmp->walk('1.3.6.1.2.1.17.4.3.1.1');
        $mac_ports = @$snmp->walk('1.3.6.1.2.1.17.4.3.1.2');
        $mac_status = @$snmp->walk('1.3.6.1.2.1.17.4.3.1.3');
        $mac_table = [];
        
        if ($mac_addrs && is_array($mac_addrs) && $mac_ports && is_array($mac_ports)) {
            $macs = array_values($mac_addrs);
            $ports = array_values($mac_ports);
            $status = $mac_status ? array_values($mac_status) : [];
            
            for ($i = 0; $i < count($macs); $i++) {
                $mac = formatMac($macs[$i]);
                $port = intval(parseSnmpValue($ports[$i]));
                if ($mac && $port > 0 && $port <= $maxPorts) {
                    $mac_table[] = [
                        'mac' => $mac,
                        'port' => $port,
                        'vlan' => 1, // VLAN bilgisi ayrı tablodan çekilebilir
                        'status' => isset($status[$i]) ? intval(parseSnmpValue($status[$i])) : 0,
                        'type' => isset($status[$i]) && intval(parseSnmpValue($status[$i])) == 3 ? 'static' : 'dynamic'
                    ];
                }
            }
        }
        $result['mac_table'] = $mac_table;
        
        // ==================== ARP TABLOSU ====================
        $arp_ip = @$snmp->walk('1.3.6.1.2.1.4.22.1.2');
        $arp_mac = @$snmp->walk('1.3.6.1.2.1.4.22.1.2');
        $arp_if = @$snmp->walk('1.3.6.1.2.1.4.22.1.2');
        $arp_table = [];
        $result['arp_table'] = $arp_table;
        
        // ==================== LLDP KOMŞULARI ====================
        $lldp_table = [];
        $lldp_names = @$snmp->walk('1.0.8802.1.1.2.1.4.1.1.9');
        $lldp_ports = @$snmp->walk('1.0.8802.1.1.2.1.4.1.1.8');
        $lldp_desc = @$snmp->walk('1.0.8802.1.1.2.1.4.1.1.10');
        $lldp_chassis = @$snmp->walk('1.0.8802.1.1.2.1.4.1.1.5');
        $lldp_cap = @$snmp->walk('1.0.8802.1.1.2.1.4.1.1.12');
        
        if ($lldp_names && is_array($lldp_names)) {
            $names = array_values($lldp_names);
            foreach ($names as $idx => $name) {
                $oid_key = array_keys($lldp_names)[$idx];
                if (preg_match('/\.(\d+)\.(\d+)$/', $oid_key, $m)) {
                    $local_port = intval($m[1]);
                    $lldp_table[$local_port] = [
                        'system_name' => parseSnmpValue($name),
                        'port_desc' => $lldp_ports ? parseSnmpValue(@$lldp_ports[$oid_key] ?? '') : '',
                        'system_desc' => $lldp_desc ? parseSnmpValue(@$lldp_desc[$oid_key] ?? '') : '',
                        'chassis_id' => $lldp_chassis ? formatMac(@$lldp_chassis[$oid_key] ?? '') : '',
                        'capabilities' => $lldp_cap ? parseSnmpValue(@$lldp_cap[$oid_key] ?? '') : ''
                    ];
                }
            }
        }
        $result['lldp'] = $lldp_table;
        
        // ==================== STP KÖK BİLGİLERİ ====================
        $result['stp'] = [
            'root_bridge' => formatMac(@$snmp->get('1.3.6.1.2.1.17.2.4.0')),
            'root_cost' => @$snmp->get('1.3.6.1.2.1.17.2.5.0'),
            'root_port' => @$snmp->get('1.3.6.1.2.1.17.2.6.0'),
            'max_age' => @$snmp->get('1.3.6.1.2.1.17.2.7.0'),
            'hello_time' => @$snmp->get('1.3.6.1.2.1.17.2.8.0'),
            'forward_delay' => @$snmp->get('1.3.6.1.2.1.17.2.9.0')
        ];
        
        // ==================== PORT-CHANNEL ====================
        $port_channels = [];
        for ($i = 1; $i <= 10; $i++) {
            $members = [];
            for ($p = 1; $p <= 28; $p++) {
                $ch_id = @$snmp->get('1.2.840.10006.300.43.1.2.1.1.12.' . $p);
                if (intval($ch_id) == $i) {
                    $members[] = $p;
                }
            }
            if (!empty($members) || @$snmp->get('1.2.840.10006.300.43.1.1.1.1.6.' . $i)) {
                $port_channels[$i] = [
                    'id' => $i,
                    'name' => 'Port-Channel' . $i,
                    'members' => $members,
                    'member_count' => count($members)
                ];
            }
        }
        $result['port_channels'] = $port_channels;
        
        // ==================== LOG KAYITLARI ====================
        $log_msgs = @$snmp->walk('1.3.6.1.4.1.9.9.41.1.2.3.1.4');
        $log_table = [];
        if ($log_msgs && is_array($log_msgs)) {
            $i = 0;
            foreach ($log_msgs as $oid => $msg) {
                if ($i++ < 50) { // Son 50 log
                    $log_table[] = [
                        'message' => parseSnmpValue($msg),
                        'severity' => @$snmp->get(str_replace('.1.4', '.1.5', $oid)) // ciscoLogSeverity
                    ];
                }
            }
        }
        $result['logs'] = $log_table;
        
        // ==================== PORT DETAYLARI ====================
        // Detect switch model to determine port range and ifIndex strategy
        $sysDescr = parseSnmpValue(@$snmp->get('1.3.6.1.2.1.1.1.0'));
        $isC9200 = (stripos($sysDescr, 'c9200') !== false || stripos($sysDescr, 'catalyst 9200') !== false);

        // Build portNum → ifIndex map for C9200L (ifIndex ≠ portNum on IOS-XE)
        // For CBS350, portNum == ifIndex, so this map is identity.
        $portIfIndexMap = [];
        if ($isC9200) {
            $ifDescrWalk = @$snmp->walk('1.3.6.1.2.1.2.2.1.2');
            if ($ifDescrWalk && is_array($ifDescrWalk)) {
                $physPorts = [];
                foreach ($ifDescrWalk as $oid => $descr) {
                    $d = parseSnmpValue($descr);
                    if (preg_match('/^(GigabitEthernet|TenGigabitEthernet|TwoGigabitEthernet)1\//i', $d)) {
                        $parts = explode('.', ltrim((string)$oid, '.'));
                        $ifIdx = intval(end($parts));
                        if ($ifIdx > 0) $physPorts[$ifIdx] = $d;
                    }
                }
                // Sort by interface name components (slot/subslot/port) to match Python worker ordering.
                // Sorting by ifIndex (ksort) gives wrong sequential port numbers on C9200L because
                // IOS-XE assigns ifIndex values that don't reflect physical port order.
                uasort($physPorts, function($a, $b) {
                    preg_match('/(\d+)\/(\d+)\/(\d+)$/', $a, $ma);
                    preg_match('/(\d+)\/(\d+)\/(\d+)$/', $b, $mb);
                    if (!$ma || !$mb) return 0;
                    if ($ma[1] != $mb[1]) return (int)$ma[1] - (int)$mb[1];
                    if ($ma[2] != $mb[2]) return (int)$ma[2] - (int)$mb[2];
                    return (int)$ma[3] - (int)$mb[3];
                });
                $seq = 1;
                foreach (array_keys($physPorts) as $ifIdx) {
                    $portIfIndexMap[$seq++] = $ifIdx;
                }
            }
        }
        $maxPorts   = $isC9200 ? count($portIfIndexMap) : 28;
        $poeMaxPort = $isC9200 ? 48 : 24;

        $active_count = 0;
        $down_count = 0;
        $poe_active = 0;
        $sfp_active = 0;
        $trunk_count = 0;
        $access_count = 0;
        
        for ($portNum = 1; $portNum <= $maxPorts; $portNum++) {
            // Use mapped ifIndex for C9200L, sequential for CBS350
            $i = isset($portIfIndexMap[$portNum]) ? $portIfIndexMap[$portNum] : $portNum;
            // IF-MIB (RFC1213)
            $ifIndex = $i;
            $ifDescr = parseSnmpValue(@$snmp->get('1.3.6.1.2.1.2.2.1.2.' . $i));
            $ifType = intval(@$snmp->get('1.3.6.1.2.1.2.2.1.3.' . $i));
            $ifMtu = intval(@$snmp->get('1.3.6.1.2.1.2.2.1.4.' . $i));
            $ifSpeed = @$snmp->get('1.3.6.1.2.1.2.2.1.5.' . $i);
            $ifPhysAddress = @$snmp->get('1.3.6.1.2.1.2.2.1.6.' . $i);
            $ifAdminStatus = intval(@$snmp->get('1.3.6.1.2.1.2.2.1.7.' . $i));
            $ifOperStatus = intval(@$snmp->get('1.3.6.1.2.1.2.2.1.8.' . $i));
            $ifLastChange = @$snmp->get('1.3.6.1.2.1.2.2.1.9.' . $i);
            
            // IF-MIB (RFC2863)
            $ifName = parseSnmpValue(@$snmp->get('1.3.6.1.2.1.31.1.1.1.1.' . $i));
            $ifHighSpeed = @$snmp->get('1.3.6.1.2.1.31.1.1.1.15.' . $i);
            $ifAlias = parseSnmpValue(@$snmp->get('1.3.6.1.2.1.31.1.1.1.18.' . $i));
            
            // Ethernet-like MIB
            $dot3StatsDuplex = @$snmp->get('1.3.6.1.2.1.10.7.2.1.19.' . $i);
            $dot3StatsFCSErrors = @$snmp->get('1.3.6.1.2.1.10.7.2.1.2.' . $i);
            $dot3StatsAlignmentErrors = @$snmp->get('1.3.6.1.2.1.10.7.2.1.1.' . $i);
            $dot3StatsSingleCollision = @$snmp->get('1.3.6.1.2.1.10.7.2.1.3.' . $i);
            $dot3StatsMultipleCollision = @$snmp->get('1.3.6.1.2.1.10.7.2.1.4.' . $i);
            $dot3StatsLateCollisions = @$snmp->get('1.3.6.1.2.1.10.7.2.1.6.' . $i);
            
            // BRIDGE-MIB (STP)
            $dot1dStpPortState = @$snmp->get('1.3.6.1.2.1.17.2.15.1.3.' . $i);
            $dot1dStpPortRole = @$snmp->get('1.3.6.1.2.1.17.2.15.1.4.' . $i);
            $dot1dStpPortPathCost = @$snmp->get('1.3.6.1.2.1.17.2.15.1.5.' . $i);
            $dot1dStpPortPriority = @$snmp->get('1.3.6.1.2.1.17.2.15.1.6.' . $i);
            $dot1dStpPortEnable = @$snmp->get('1.3.6.1.2.1.17.2.15.1.2.' . $i);
            
            // Q-BRIDGE-MIB (VLAN)
            $dot1qPvid = intval(parseSnmpValue(@$snmp->get('1.3.6.1.2.1.17.7.1.4.5.1.1.' . $i)));
            
            // CISCO-VLAN-MEMBERSHIP-MIB
            $vmVlan = @$snmp->get('1.3.6.1.4.1.9.9.68.1.2.2.1.2.' . $i);
            $vmVlanType = @$snmp->get('1.3.6.1.4.1.9.9.68.1.2.2.1.3.' . $i);
            
            // CISCO-PORT-SECURITY-MIB
            $cpsIfPortSecurityEnable = @$snmp->get('1.3.6.1.4.1.9.9.315.1.2.1.1.1.' . $i);
            $cpsIfPortSecurityMaxMacs = @$snmp->get('1.3.6.1.4.1.9.9.315.1.2.1.1.4.' . $i);
            $cpsIfPortSecurityCurrentMacs = @$snmp->get('1.3.6.1.4.1.9.9.315.1.2.1.1.5.' . $i);
            
            // CISCO-STORM-CONTROL-MIB
            $cswStormControlBroadcast = @$snmp->get('1.3.6.1.4.1.9.9.215.1.1.1.1.4.' . $i);
            $cswStormControlMulticast = @$snmp->get('1.3.6.1.4.1.9.9.215.1.1.1.2.4.' . $i);
            $cswStormControlUnicast = @$snmp->get('1.3.6.1.4.1.9.9.215.1.1.1.3.4.' . $i);
            
            // CISCO-PRIVATE-VLAN-MIB
            $cswSwitchPortIsolation = @$snmp->get('1.3.6.1.4.1.9.9.276.1.4.2.1.1.8.' . $i);
            
            // CISCO-IGMP-SNOOPING-MIB
            $cIgmpSnoopingPortFastLeave = @$snmp->get('1.3.6.1.4.1.9.9.306.1.2.1.1.4.' . $i);
            $cIgmpSnoopingPortRouterPort = @$snmp->get('1.3.6.1.4.1.9.9.306.1.2.1.1.3.' . $i);
            
            // POWER-ETHERNET-MIB (PoE)
            $pethPsePortAdminEnable = null;
            $pethPsePortPower = null;
            $pethPsePortClass = null;
            $pethPsePortPriority = null;
            
            if ($portNum <= $poeMaxPort) {
                $pethPsePortAdminEnable = @$snmp->get('1.3.6.1.2.1.105.1.1.1.3.' . $i);
                $pethPsePortPower = @$snmp->get('1.3.6.1.2.1.105.1.1.1.7.' . $i);
                $pethPsePortClass = @$snmp->get('1.3.6.1.2.1.105.1.1.1.5.' . $i);
                $pethPsePortPriority = @$snmp->get('1.3.6.1.2.1.105.1.1.1.4.' . $i);
            }
            
            // ETHERLIKE-MIB (Flow Control)
            $dot3StatsPauseFrames = @$snmp->get('1.3.6.1.2.1.10.7.2.1.11.' . $i);
            
            // LAG-MIB (Port Channel)
            $dot3adAggPortAttachedAggID = @$snmp->get('1.2.840.10006.300.43.1.2.1.1.12.' . $i);
            $dot3adAggPortPartnerOperState = @$snmp->get('1.2.840.10006.300.43.1.2.1.1.10.' . $i);
            
            // VLAN'dan port'un üye olduğu VLAN'ları bul
            $port_vlans = [];
            $primary_vlan = 1;
            
            if ($isC9200) {
                // C9200L: use dot1qPvid (indexed by ifIndex) directly
                if ($dot1qPvid > 1) { $primary_vlan = $dot1qPvid; $port_vlans = [$dot1qPvid]; }
                else { $vm = intval(parseSnmpValue(@$snmp->get('1.3.6.1.4.1.9.9.68.1.2.2.1.2.' . $i)));
                       if ($vm > 1) { $primary_vlan = $vm; $port_vlans = [$vm]; }
                       else { $port_vlans = [1]; } }
            } else {
                // CBS350: Q-BRIDGE untagged mask (portNum=ifIndex, bitmap works)
                foreach ($vlan_map as $vid => $vlan) {
                    if (in_array($portNum, $vlan['member_ports'])) {
                        $port_vlans[] = $vid;
                        if ($vid != 1) $primary_vlan = $vid;
                    }
                }
                if (empty($port_vlans) && $dot1qPvid) {
                    $port_vlans[] = $dot1qPvid;
                    $primary_vlan = $dot1qPvid;
                }
            }
            
            // Port tipi
            $port_type = ($portNum <= ($poeMaxPort ?: 24)) ? 'PoE' : 'SFP';
            
            // Durum
            $is_active = ($ifOperStatus == 1);
            if ($is_active) {
                $active_count++;
                if ($port_type == 'PoE') $poe_active++; else $sfp_active++;
            }
            if ($ifOperStatus == 2) $down_count++;
            
            // MAC sayısı
            $mac_count = 0;
            foreach ($mac_table as $mac_entry) {
                if ($mac_entry['port'] == $portNum) $mac_count++;
            }
            
            // Trafik sayıcıları
            $ifInOctets = @$snmp->get('1.3.6.1.2.1.2.2.1.10.' . $i);
            $ifOutOctets = @$snmp->get('1.3.6.1.2.1.2.2.1.16.' . $i);
            $ifInUcastPkts = @$snmp->get('1.3.6.1.2.1.2.2.1.11.' . $i);
            $ifOutUcastPkts = @$snmp->get('1.3.6.1.2.1.2.2.1.17.' . $i);
            $ifInNUcastPkts = @$snmp->get('1.3.6.1.2.1.2.2.1.12.' . $i);
            $ifOutNUcastPkts = @$snmp->get('1.3.6.1.2.1.2.2.1.18.' . $i);
            $ifInDiscards = @$snmp->get('1.3.6.1.2.1.2.2.1.13.' . $i);
            $ifOutDiscards = @$snmp->get('1.3.6.1.2.1.2.2.1.19.' . $i);
            $ifInErrors = @$snmp->get('1.3.6.1.2.1.2.2.1.14.' . $i);
            $ifOutErrors = @$snmp->get('1.3.6.1.2.1.2.2.1.20.' . $i);
            $ifInUnknownProtos = @$snmp->get('1.3.6.1.2.1.2.2.1.15.' . $i);
            
            // HC (64-bit) sayıcılar
            $ifHCInOctets = @$snmp->get('1.3.6.1.2.1.31.1.1.1.6.' . $i);
            $ifHCOutOctets = @$snmp->get('1.3.6.1.2.1.31.1.1.1.10.' . $i);
            
            $result['ports'][$portNum] = [
                // Temel Bilgiler
                'index' => $portNum,
                'if_index' => $i,
                'descr' => $ifDescr ?: "GE$i",
                'name' => $ifName ?: "GE$i",
                'alias' => $ifAlias,
                'type' => $port_type,
                'if_type' => $ifType,
                'if_type_text' => ifType($ifType),
                'mtu' => $ifMtu,
                'mac' => formatMac($ifPhysAddress),
                'speed' => formatSpeed($ifSpeed),
                'speed_raw' => intval($ifSpeed),
                'high_speed' => intval($ifHighSpeed),
                
                // Durum
                'admin' => $ifAdminStatus,
                'admin_text' => $ifAdminStatus == 1 ? 'up' : 'down',
                'oper' => $ifOperStatus,
                'oper_text' => $ifOperStatus == 1 ? 'up' : ($ifOperStatus == 2 ? 'down' : 'unknown'),
                'is_active' => $is_active,
                'last_change' => formatUptime($ifLastChange),
                'last_change_raw' => intval($ifLastChange),
                
                // Duplex
                'duplex' => duplex($dot3StatsDuplex),
                'duplex_raw' => intval($dot3StatsDuplex),
                
                // VLAN
                'pvid' => $dot1qPvid,
                'vlan' => $primary_vlan,
                'vlans' => $port_vlans,
                'vlan_count' => count($port_vlans),
                'vm_vlan' => intval(parseSnmpValue($vmVlan)),
                'vm_vlan_type' => intval(parseSnmpValue($vmVlanType)),
                
                // STP
                'stp_state' => stpState($dot1dStpPortState),
                'stp_state_raw' => intval($dot1dStpPortState),
                'stp_role' => stpRole($dot1dStpPortRole),
                'stp_role_raw' => intval($dot1dStpPortRole),
                'stp_path_cost' => intval($dot1dStpPortPathCost),
                'stp_priority' => intval($dot1dStpPortPriority),
                'stp_enabled' => intval($dot1dStpPortEnable) == 1,
                
                // Port Security
                'port_security' => intval($cpsIfPortSecurityEnable) == 1,
                'port_security_max' => intval($cpsIfPortSecurityMaxMacs),
                'port_security_current' => intval($cpsIfPortSecurityCurrentMacs),
                'mac_count' => $mac_count,
                
                // Storm Control
                'storm_broadcast' => intval($cswStormControlBroadcast) == 1,
                'storm_multicast' => intval($cswStormControlMulticast) == 1,
                'storm_unicast' => intval($cswStormControlUnicast) == 1,
                
                // Private VLAN
                'port_isolation' => intval($cswSwitchPortIsolation) == 1,
                
                // IGMP
                'igmp_fast_leave' => intval($cIgmpSnoopingPortFastLeave) == 1,
                'igmp_router' => intval($cIgmpSnoopingPortRouterPort) == 1,
                
                // PoE
                'poe_enabled' => ($portNum <= $poeMaxPort) ? (intval($pethPsePortAdminEnable) == 1) : null,
                'poe_power' => ($portNum <= $poeMaxPort) ? intval($pethPsePortPower) : null,
                'poe_power_watt' => ($portNum <= $poeMaxPort && $pethPsePortPower) ? round(intval($pethPsePortPower)/1000,1).' W' : null,
                'poe_class' => ($portNum <= $poeMaxPort) ? intval($pethPsePortClass) : null,
                'poe_class_text' => ($portNum <= $poeMaxPort) ? poeClass(intval($pethPsePortClass)) : null,
                'poe_priority' => ($portNum <= $poeMaxPort) ? intval($pethPsePortPriority) : null,
                
                // Flow Control
                'pause_frames' => intval($dot3StatsPauseFrames),
                
                // Port Channel
                'channel_id' => intval($dot3adAggPortAttachedAggID),
                'channel_member' => intval($dot3adAggPortAttachedAggID) > 0,
                'channel_state' => intval($dot3adAggPortPartnerOperState),
                
                // LLDP Komşu
                'lldp' => $lldp_table[$portNum] ?? $lldp_table[$i] ?? null,
                
                // Trafik (32-bit)
                'in_octets' => intval($ifInOctets),
                'out_octets' => intval($ifOutOctets),
                'in_traffic' => formatBytes($ifInOctets),
                'out_traffic' => formatBytes($ifOutOctets),
                'in_ucast' => intval($ifInUcastPkts),
                'out_ucast' => intval($ifOutUcastPkts),
                'in_nucast' => intval($ifInNUcastPkts),
                'out_nucast' => intval($ifOutNUcastPkts),
                'in_discards' => intval($ifInDiscards),
                'out_discards' => intval($ifOutDiscards),
                'in_errors' => intval($ifInErrors),
                'out_errors' => intval($ifOutErrors),
                'in_unknown' => intval($ifInUnknownProtos),
                
                // Trafik (64-bit)
                'in_octets_64' => intval($ifHCInOctets),
                'out_octets_64' => intval($ifHCOutOctets),
                
                // Hata detayları
                'crc_errors' => intval($dot3StatsFCSErrors) + intval($dot3StatsAlignmentErrors),
                'fcs_errors' => intval($dot3StatsFCSErrors),
                'align_errors' => intval($dot3StatsAlignmentErrors),
                'single_collisions' => intval($dot3StatsSingleCollision),
                'multiple_collisions' => intval($dot3StatsMultipleCollision),
                'late_collisions' => intval($dot3StatsLateCollisions),
            ];
        }
        
        // ==================== İSTATİSTİKLER ====================
        $result['stats'] = [
            'total_ports' => $maxPorts,
            'poe_ports' => $poeMaxPort,
            'sfp_ports' => $maxPorts - $poeMaxPort,
            'active_ports' => $active_count,
            'active_poe' => $poe_active,
            'active_sfp' => $sfp_active,
            'down_ports' => $down_count,
            'active_percent' => $maxPorts > 0 ? round(($active_count / $maxPorts) * 100, 1) : 0,
            'active_list' => array_keys(array_filter($result['ports'], fn($p) => $p['is_active'])),
            'total_mac' => count($mac_table),
            'total_vlans' => count($vlan_map),
            'total_lldp' => count($lldp_table)
        ];
        
        $result['success'] = true;
        
    } catch (Exception $e) {
        $result['error'] = 'SNMP Hatası: ' . $e->getMessage();
    }
    
    while (ob_get_level()) ob_end_clean();
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_IGNORE);
    exit;
}

// HTML ÇIKTISI
if (!isAjax()) {
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CBS350-24FP - TÜM SNMP VERİLERİ</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Segoe UI',sans-serif; background:linear-gradient(135deg,#667eea 0%,#764ba2 100%); padding:20px; }
        .container { max-width:1600px; margin:0 auto; }
        .header { background:white; padding:25px; border-radius:15px; box-shadow:0 10px 30px rgba(0,0,0,0.2); margin-bottom:20px; text-align:center; }
        .header h1 { color:#667eea; font-size:28px; margin-bottom:10px; }
        .badge-success { background:#28a745; color:white; padding:8px 20px; border-radius:25px; display:inline-block; margin-top:10px; }
        .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:15px; margin-bottom:20px; }
        .stat-card { background:linear-gradient(135deg,#667eea 0%,#764ba2 100%); color:white; padding:20px; border-radius:15px; text-align:center; }
        .stat-value { font-size:28px; font-weight:bold; margin:10px 0; }
        .port-grid { display:grid; grid-template-columns:repeat(7,1fr); gap:10px; margin-top:20px; }
        .port-card { background:white; padding:12px; border-radius:10px; text-align:center; cursor:pointer; transition:all 0.3s; border:2px solid transparent; position:relative; }
        .port-card:hover { transform:translateY(-3px); box-shadow:0 5px 15px rgba(0,0,0,0.2); border-color:#667eea; }
        .port-card.up { background:#d4edda; }
        .port-card.down { background:#f8d7da; }
        .port-card.admin-down { background:#fff3cd; }
        .port-number { font-size:16px; font-weight:bold; margin-bottom:5px; }
        .port-type { font-size:11px; padding:2px 6px; background:rgba(0,0,0,0.1); border-radius:10px; display:inline-block; margin-top:5px; }
        .status-icon { font-size:20px; margin:8px 0; }
        .system-info { background:white; padding:20px; border-radius:15px; margin-bottom:20px; display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:15px; }
        .info-item { padding:10px; background:#f8f9fa; border-radius:8px; border-left:4px solid #667eea; }
        .info-item label { font-weight:bold; color:#555; font-size:12px; display:block; margin-bottom:5px; }
        .btn { background:#667eea; color:white; border:none; padding:12px 24px; border-radius:8px; font-weight:bold; cursor:pointer; margin:5px; transition:all 0.3s; }
        .btn:hover { background:#5568d3; transform:translateY(-2px); }
        .btn-success { background:#28a745; }
        .btn-success:hover { background:#218838; }
        .active-ports { background:white; padding:20px; border-radius:15px; margin-top:20px; }
        .port-tag { display:inline-block; padding:6px 15px; background:#28a745; color:white; border-radius:20px; margin:5px; font-size:13px; }
        .loading { text-align:center; padding:40px; }
        .spinner { border:4px solid #f3f3f3; border-top:4px solid #667eea; border-radius:50%; width:50px; height:50px; animation:spin 1s linear infinite; margin:0 auto 20px; }
        @keyframes spin { 0%{transform:rotate(0deg);} 100%{transform:rotate(360deg);} }
        .vlan-badge { display:inline-block; padding:2px 8px; background:#667eea; color:white; border-radius:12px; font-size:10px; font-weight:bold; margin-top:5px; }
        .poe-indicator { position:absolute; top:5px; right:5px; color:#ffc107; font-size:12px; }
        .tabs { display:flex; gap:10px; margin-bottom:20px; flex-wrap:wrap; }
        .tab { background:white; padding:10px 20px; border-radius:8px; cursor:pointer; font-weight:bold; transition:all 0.3s; }
        .tab.active { background:#667eea; color:white; }
        .detail-section { background:white; padding:20px; border-radius:15px; margin-bottom:20px; display:none; }
        .modal { position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.7); z-index:1000; overflow-y:auto; padding:20px; }
        .modal-content { background:white; max-width:900px; margin:20px auto; border-radius:15px; padding:25px; }
        .property-group { background:#f8f9fa; border-radius:10px; padding:15px; margin-bottom:15px; }
        .property-group h4 { color:#667eea; margin-bottom:10px; }
        .error { background:#f8d7da; color:#721c24; padding:15px; border-radius:8px; margin-bottom:20px; text-align:center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-network-wired"></i> EDGE-SW35 - CBS350-24FP</h1>
            <p>TÜM SNMP VERİLERİ | 50+ Parametre/Port</p>
            <span class="badge-success" id="status"><i class="fas fa-sync-alt fa-spin"></i> Yükleniyor...</span>
        </div>
        
        <div style="text-align:center; margin-bottom:20px;">
            <button class="btn" onclick="loadData()"><i class="fas fa-sync-alt"></i> Yenile</button>
            <button class="btn btn-success" onclick="setPasswords()"><i class="fas fa-key"></i> Şifre Değiştir</button>
            <button class="btn" onclick="exportJSON()"><i class="fas fa-download"></i> JSON İndir</button>
        </div>
        
        <div id="error" class="error" style="display:none;"></div>
        
        <div id="systemInfo" class="system-info"></div>
        <div id="stats"></div>
        
        <div class="tabs">
            <div class="tab active" onclick="showTab('ports')">Portlar</div>
            <div class="tab" onclick="showTab('poe')">PoE</div>
            <div class="tab" onclick="showTab('vlan')">VLAN</div>
            <div class="tab" onclick="showTab('stp')">STP</div>
            <div class="tab" onclick="showTab('security')">Güvenlik</div>
            <div class="tab" onclick="showTab('mac')">MAC</div>
            <div class="tab" onclick="showTab('lldp')">LLDP</div>
            <div class="tab" onclick="showTab('errors')">Hatalar</div>
        </div>
        
        <div id="ports-tab" class="detail-section" style="display:block;">
            <h2><i class="fas fa-plug"></i> Portlar (1-28)</h2>
            <div class="port-grid" id="portGrid"></div>
        </div>
        
        <div id="poe-tab" class="detail-section"></div>
        <div id="vlan-tab" class="detail-section"></div>
        <div id="stp-tab" class="detail-section"></div>
        <div id="security-tab" class="detail-section"></div>
        <div id="mac-tab" class="detail-section"></div>
        <div id="lldp-tab" class="detail-section"></div>
        <div id="errors-tab" class="detail-section"></div>
        
        <div class="active-ports">
            <h2><i class="fas fa-check-circle"></i> Aktif Portlar</h2>
            <div id="activePorts"></div>
        </div>
    </div>
    
    <script>
        let authPass = 'AuthPass123';
        let privPass = 'PrivPass123';
        let data = null;
        
        function setPasswords() {
            let a = prompt('Auth Password:', authPass);
            if (a) { authPass = a;
                let p = prompt('Priv Password:', privPass);
                if (p) { privPass = p; loadData(); }
            }
        }
        
        async function loadData() {
            document.getElementById('status').innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Yükleniyor...';
            document.getElementById('error').style.display = 'none';
            
            try {
                let res = await fetch(window.location.href, {
                    method: 'POST',
                    headers: {'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
                    body: JSON.stringify({action:'get_all_data', auth_password:authPass, priv_password:privPass})
                });
                
                let text = await res.text();
                try { data = JSON.parse(text); } catch(e) { 
                    console.error(text.substring(0,500)); 
                    throw new Error('JSON parse hatası - Sunucu yanıtı geçersiz'); 
                }
                
                if (data.success) {
                    let statusHtml = '<i class="fas fa-check-circle"></i> Başarılı';
                    if (data.data_source === 'db') {
                        statusHtml = '<i class="fas fa-database"></i> Veritabanından (PHP SNMP yok)';
                        document.getElementById('status').style.background = '#17a2b8';
                    }
                    document.getElementById('status').innerHTML = statusHtml;
                    renderAll();
                } else {
                    showError(data.error || 'Bilinmeyen hata');
                }
            } catch(e) {
                showError('Bağlantı hatası: ' + e.message);
            }
        }
        
        function showError(msg) {
            document.getElementById('error').innerHTML = '<i class="fas fa-exclamation-triangle"></i> ' + msg;
            document.getElementById('error').style.display = 'block';
            document.getElementById('status').innerHTML = '<i class="fas fa-times-circle"></i> Hata';
        }
        
        function renderAll() {
            if (!data) return;
            renderSystem();
            renderStats();
            renderPorts();
            renderActivePorts();
            renderPoe();
            renderVlan();
            renderStp();
            renderSecurity();
            renderMac();
            renderLldp();
            renderErrors();
        }
        
        function renderSystem() {
            let s = data.system;
            let html = `
                <div class="info-item"><label>Switch</label><div>${s.name||'N/A'}</div></div>
                <div class="info-item"><label>Model</label><div>${s.descr?.split(',')[0]||'N/A'}</div></div>
                <div class="info-item"><label>Seri No</label><div>${data.chassis.serial||'N/A'}</div></div>
                <div class="info-item"><label>Çalışma</label><div>${s.uptime_text||'N/A'}</div></div>
                <div class="info-item"><label>Lokasyon</label><div>${s.location||'N/A'}</div></div>
                <div class="info-item"><label>MAC</label><div>${data.chassis.mac||'N/A'}</div></div>
            `;
            document.getElementById('systemInfo').innerHTML = html;
        }
        
        function renderStats() {
            let st = data.stats;
            let html = `<div class="stats-grid">
                <div class="stat-card"><i class="fas fa-plug"></i><div class="stat-value">${st.total_ports}</div><div>Toplam</div></div>
                <div class="stat-card" style="background:linear-gradient(135deg,#28a745,#20c997)"><i class="fas fa-check-circle"></i><div class="stat-value">${st.active_ports}</div><div>Aktif</div></div>
                <div class="stat-card" style="background:linear-gradient(135deg,#dc3545,#c82333)"><i class="fas fa-times-circle"></i><div class="stat-value">${st.down_ports}</div><div>Pasif</div></div>
                <div class="stat-card" style="background:linear-gradient(135deg,#17a2b8,#138496)"><i class="fas fa-percentage"></i><div class="stat-value">${st.active_percent}%</div><div>Kullanım</div></div>
                <div class="stat-card" style="background:linear-gradient(135deg,#ffc107,#e0a800)"><i class="fas fa-bolt"></i><div class="stat-value">${st.active_poe}</div><div>PoE Aktif</div></div>
                <div class="stat-card" style="background:linear-gradient(135deg,#6f42c1,#5a32a3)"><i class="fas fa-sitemap"></i><div class="stat-value">${st.total_lldp}</div><div>LLDP</div></div>
            </div>`;
            document.getElementById('stats').innerHTML = html;
        }
        
        function renderPorts() {
            let html = '';
            for(let i=1; i<=data.stats.total_ports; i++) {
                let p = data.ports[i]; if(!p) continue;
                let cls = p.oper==1?'up':(p.oper==2?'down':'admin-down');
                let icon = p.oper==1?'fa-check-circle':(p.oper==2?'fa-times-circle':'fa-pause-circle');
                let col = p.oper==1?'#28a745':(p.oper==2?'#dc3545':'#ffc107');
                let poe = (p.type=='PoE' && p.poe_enabled) ? '<span class="poe-indicator"><i class="fas fa-bolt"></i></span>' : '';
                let vlan = p.vlan ? `<div class="vlan-badge">VLAN ${p.vlan}</div>` : '';
                html += `<div class="port-card ${cls}" onclick="showPortDetail(${i})">
                    ${poe}<div class="port-number">GE${i}</div>
                    <div class="status-icon"><i class="fas ${icon}" style="color:${col}"></i></div>
                    <div class="port-type">${p.type}</div>
                    <div style="font-size:11px">${p.speed}</div>${vlan}
                </div>`;
            }
            document.getElementById('portGrid').innerHTML = html;
        }
        
        function renderActivePorts() {
            if(!data.stats.active_list?.length) {
                document.getElementById('activePorts').innerHTML = '<p>Aktif port yok</p>';
                return;
            }
            let html = '<div style="display:flex;flex-wrap:wrap">';
            data.stats.active_list.sort().forEach(p => {
                let port = data.ports[p];
                html += `<span class="port-tag"><i class="fas fa-plug"></i> GE${p} (VLAN ${port.vlan})</span>`;
            });
            html += '</div>';
            document.getElementById('activePorts').innerHTML = html;
        }
        
        function renderPoe() {
            let html = '<h2><i class="fas fa-bolt"></i> PoE Portları</h2><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px">';
            for(let i=1; i<=data.stats.poe_ports; i++) {
                let p = data.ports[i];
                if(!p) continue;
                html += `<div class="property-group">
                    <h4>GE${i} - ${p.name}</h4>
                    <div><strong>Durum:</strong> <span style="color:${p.poe_enabled?'#28a745':'#dc3545'}">${p.poe_enabled?'Aktif':'Pasif'}</span></div>
                    <div><strong>Güç:</strong> ${p.poe_power_watt||'0 W'}</div>
                    <div><strong>Sınıf:</strong> ${p.poe_class_text||'N/A'}</div>
                    <div><strong>Öncelik:</strong> ${p.poe_priority||'N/A'}</div>
                </div>`;
            }
            html += '</div>';
            document.getElementById('poe-tab').innerHTML = html;
        }
        
        function renderVlan() {
            let html = '<h2><i class="fas fa-network-wired"></i> VLAN Bilgileri</h2><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px">';
            for(let i=1; i<=data.stats.total_ports; i++) {
                let p = data.ports[i];
                if(!p) continue;
                html += `<div class="property-group">
                    <h4>GE${i}</h4>
                    <div><strong>PVID:</strong> <span style="background:#667eea;color:white;padding:2px 8px;border-radius:12px">${p.vlan}</span></div>
                    <div><strong>Üye VLANlar:</strong> ${p.vlans?.join(', ')||p.vlan}</div>
                    <div><strong>VLAN Sayısı:</strong> ${p.vlan_count}</div>
                </div>`;
            }
            html += '</div>';
            document.getElementById('vlan-tab').innerHTML = html;
        }
        
        function renderStp() {
            let html = '<h2><i class="fas fa-code-branch"></i> STP Durumu</h2><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px">';
            for(let i=1; i<=data.stats.total_ports; i++) {
                let p = data.ports[i];
                if(!p) continue;
                html += `<div class="property-group">
                    <h4>GE${i}</h4>
                    <div><strong>Durum:</strong> ${p.stp_state}</div>
                    <div><strong>Rol:</strong> ${p.stp_role}</div>
                    <div><strong>Path Cost:</strong> ${p.stp_path_cost}</div>
                    <div><strong>Öncelik:</strong> ${p.stp_priority}</div>
                </div>`;
            }
            html += '</div>';
            document.getElementById('stp-tab').innerHTML = html;
        }
        
        function renderSecurity() {
            let html = '<h2><i class="fas fa-shield-alt"></i> Port Güvenlik</h2><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px">';
            for(let i=1; i<=data.stats.total_ports; i++) {
                let p = data.ports[i];
                if(!p) continue;
                html += `<div class="property-group">
                    <h4>GE${i}</h4>
                    <div><strong>Port Security:</strong> ${p.port_security?'Aktif':'Pasif'}</div>
                    <div><strong>Max MAC:</strong> ${p.port_security_max||'Sınırsız'}</div>
                    <div><strong>Öğrenilen MAC:</strong> ${p.port_security_current||0}</div>
                    <div><strong>MAC Sayısı:</strong> ${p.mac_count}</div>
                    <div><strong>İzolasyon:</strong> ${p.port_isolation?'Aktif':'Pasif'}</div>
                </div>`;
            }
            html += '</div>';
            document.getElementById('security-tab').innerHTML = html;
        }
        
        function renderMac() {
            let byPort = {};
            data.mac_table.forEach(m => { if(!byPort[m.port]) byPort[m.port]=[]; byPort[m.port].push(m.mac); });
            let html = '<h2><i class="fas fa-address-book"></i> MAC Tablosu</h2><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px">';
            for(let i=1; i<=28; i++) {
                if(!byPort[i]?.length) continue;
                html += `<div class="property-group">
                    <h4>GE${i} - ${byPort[i].length} MAC</h4>
                    <div style="max-height:150px;overflow-y:auto">${byPort[i].map(m=>`<div style="font-family:monospace">${m}</div>`).join('')}</div>
                </div>`;
            }
            html += '</div>';
            document.getElementById('mac-tab').innerHTML = html;
        }
        
        function renderLldp() {
            let html = '<h2><i class="fas fa-sitemap"></i> LLDP Komşular</h2><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px">';
            for(let i=1; i<=28; i++) {
                let l = data.lldp[i];
                if(!l) continue;
                html += `<div class="property-group">
                    <h4>GE${i}</h4>
                    <div><strong>Cihaz:</strong> ${l.system_name||'N/A'}</div>
                    <div><strong>Port:</strong> ${l.port_desc||'N/A'}</div>
                    <div><strong>Model:</strong> ${l.system_desc?.substring(0,50)||'N/A'}</div>
                </div>`;
            }
            html += '</div>';
            document.getElementById('lldp-tab').innerHTML = html;
        }
        
        function renderErrors() {
            let html = '<h2><i class="fas fa-exclamation-triangle"></i> Hata İstatistikleri</h2><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px">';
            for(let i=1; i<=28; i++) {
                let p = data.ports[i];
                if(!p) continue;
                let hasErr = p.in_errors>0||p.out_errors>0||p.crc_errors>0;
                html += `<div class="property-group" style="${hasErr?'border-left:4px solid #dc3545':''}">
                    <h4>GE${i}</h4>
                    <div><strong>Gelen Hata:</strong> ${p.in_errors}</div>
                    <div><strong>Giden Hata:</strong> ${p.out_errors}</div>
                    <div><strong>CRC Hata:</strong> ${p.crc_errors}</div>
                    <div><strong>Collisions:</strong> ${p.single_collisions+p.multiple_collisions}</div>
                    <div><strong>Late Collisions:</strong> ${p.late_collisions}</div>
                </div>`;
            }
            html += '</div>';
            document.getElementById('errors-tab').innerHTML = html;
        }
        
        function showPortDetail(i) {
            let p = data.ports[i];
            if(!p) return;
            let l = data.lldp[i];
            let html = `
                <div class="modal" onclick="if(event.target===this)this.remove()">
                    <div class="modal-content">
                        <div style="display:flex;justify-content:space-between;margin-bottom:20px">
                            <h2 style="color:#667eea"><i class="fas fa-plug"></i> GE${i} Detayları</h2>
                            <button onclick="this.closest('.modal').remove()" style="background:#dc3545;color:white;border:none;padding:8px 16px;border-radius:5px">Kapat</button>
                        </div>
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:15px">
                            <div class="property-group"><h4>Temel</h4>
                                <div><strong>Ad:</strong> ${p.name}</div>
                                <div><strong>Açıklama:</strong> ${p.alias||'Yok'}</div>
                                <div><strong>Tip:</strong> ${p.type} (${p.if_type_text})</div>
                                <div><strong>MAC:</strong> ${p.mac||'N/A'}</div>
                                <div><strong>MTU:</strong> ${p.mtu}</div>
                                <div><strong>Hız:</strong> ${p.speed}</div>
                                <div><strong>Duplex:</strong> ${p.duplex}</div>
                            </div>
                            <div class="property-group"><h4>Durum</h4>
                                <div><strong>Oper:</strong> <span style="color:${p.oper==1?'#28a745':'#dc3545'}">${p.oper_text}</span></div>
                                <div><strong>Admin:</strong> ${p.admin_text}</div>
                                <div><strong>Son Değişim:</strong> ${p.last_change}</div>
                            </div>
                            <div class="property-group"><h4>VLAN</h4>
                                <div><strong>PVID:</strong> <span style="background:#667eea;color:white;padding:2px 8px;border-radius:12px">${p.vlan}</span></div>
                                <div><strong>dot1qPvid:</strong> ${p.pvid}</div>
                                <div><strong>Üye VLANlar:</strong> ${p.vlans?.join(', ')}</div>
                            </div>
                            <div class="property-group"><h4>STP</h4>
                                <div><strong>Durum:</strong> ${p.stp_state}</div>
                                <div><strong>Rol:</strong> ${p.stp_role}</div>
                                <div><strong>Cost:</strong> ${p.stp_path_cost}</div>
                                <div><strong>Priority:</strong> ${p.stp_priority}</div>
                            </div>
                            ${p.type=='PoE'?`
                            <div class="property-group"><h4>PoE</h4>
                                <div><strong>Durum:</strong> ${p.poe_enabled?'Aktif':'Pasif'}</div>
                                <div><strong>Güç:</strong> ${p.poe_power_watt||'0W'}</div>
                                <div><strong>Sınıf:</strong> ${p.poe_class_text||'N/A'}</div>
                            </div>`:''}
                            <div class="property-group"><h4>Trafik</h4>
                                <div><strong>Gelen:</strong> ${p.in_traffic}</div>
                                <div><strong>Giden:</strong> ${p.out_traffic}</div>
                                <div><strong>Gelen Paket:</strong> ${p.in_ucast?.toLocaleString()}</div>
                                <div><strong>Giden Paket:</strong> ${p.out_ucast?.toLocaleString()}</div>
                                <div><strong>Gelen Hata:</strong> ${p.in_errors}</div>
                                <div><strong>Giden Hata:</strong> ${p.out_errors}</div>
                                <div><strong>CRC Hata:</strong> ${p.crc_errors}</div>
                            </div>
                            <div class="property-group"><h4>Güvenlik</h4>
                                <div><strong>Port Security:</strong> ${p.port_security?'Aktif':'Pasif'}</div>
                                <div><strong>Max MAC:</strong> ${p.port_security_max||'Sınırsız'}</div>
                                <div><strong>Öğrenilen MAC:</strong> ${p.port_security_current||0}</div>
                                <div><strong>MAC Sayısı:</strong> ${p.mac_count}</div>
                            </div>
                            <div class="property-group"><h4>Storm Control</h4>
                                <div><strong>Broadcast:</strong> ${p.storm_broadcast?'Aktif':'Pasif'}</div>
                                <div><strong>Multicast:</strong> ${p.storm_multicast?'Aktif':'Pasif'}</div>
                                <div><strong>Unicast:</strong> ${p.storm_unicast?'Aktif':'Pasif'}</div>
                            </div>
                            ${l?`
                            <div class="property-group"><h4>LLDP Komşu</h4>
                                <div><strong>Cihaz:</strong> ${l.system_name}</div>
                                <div><strong>Port:</strong> ${l.port_desc}</div>
                                <div><strong>Model:</strong> ${l.system_desc?.substring(0,100)}</div>
                            </div>`:''}
                        </div>
                    </div>
                </div>
            `;
            document.body.insertAdjacentHTML('beforeend', html);
        }
        
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
            document.querySelectorAll('.detail-section').forEach(s=>s.style.display='none');
            document.querySelector(`.tab[onclick*="${tab}"]`).classList.add('active');
            document.getElementById(tab+'-tab').style.display = 'block';
        }
        
        function exportJSON() {
            if(!data) return alert('Önce verileri yükleyin');
            let blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'});
            let a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'switch_data.json';
            a.click();
        }
        
        document.addEventListener('DOMContentLoaded', loadData);
    </script>
</body>
</html>
<?php
}
?>