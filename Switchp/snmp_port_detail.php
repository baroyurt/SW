<?php
/**
 * snmp_port_detail.php — Tek port için SNMP detay verileri
 * Kullanım: POST JSON {"switch_id": 93, "port": 20}
 */
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

header('Content-Type: application/json; charset=utf-8');
header("Cache-Control: no-cache, no-store, must-revalidate");

function parseSnmpValue($value) {
    if (empty($value) || $value === false) return '';
    $value = trim($value);
    if (preg_match('/^"(.*)"$/s', $value, $m)) return $m[1];
    if (preg_match('/^(STRING|INTEGER|Gauge32|Counter32|Counter64|TimeTicks|IpAddress|Hex-STRING|OID|Timeticks):\s*(.+)$/s', $value, $m)) {
        $v = trim($m[2]);
        if (preg_match('/^"(.*)"$/s', $v, $m2)) return $m2[1];
        return $v;
    }
    return $value;
}

function formatMac($v) {
    $v = trim(parseSnmpValue($v));
    $clean = preg_replace('/[^a-fA-F0-9]/', '', $v);
    if (strlen($clean) !== 12) return '';
    return implode(':', str_split($clean, 2));
}

function formatSpeed($s) {
    $s = intval($s);
    if ($s <= 0) return '-';
    if ($s >= 1000000000) return round($s/1000000000).' Gbps';
    if ($s >= 1000000) return round($s/1000000).' Mbps';
    if ($s >= 1000) return round($s/1000).' Kbps';
    return $s.' bps';
}

function formatBytes($b) {
    if (!$b) return '0 B';
    $b = intval($b);
    $u = ['B','KB','MB','GB','TB'];
    $i = 0;
    while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; }
    return round($b, 2).' '.$u[$i];
}

function formatUptime($v) {
    $v = parseSnmpValue($v);
    if (empty($v)) return '-';
    // TimeTicks: (12345678) 1:25:31:18.78  or just number
    if (preg_match('/\((\d+)\)/', $v, $m)) $ticks = intval($m[1]);
    else $ticks = intval($v);
    if ($ticks <= 0) return '-';
    $s = intval($ticks / 100);
    $d = intdiv($s, 86400); $s %= 86400;
    $h = intdiv($s, 3600);  $s %= 3600;
    $m = intdiv($s, 60);    $s %= 60;
    return ($d > 0 ? "{$d}g " : '') . sprintf('%02d:%02d:%02d', $h, $m, $s);
}

function duplex($v) {
    $v = intval(parseSnmpValue($v));
    return match($v) { 1=>'unknown', 2=>'half-duplex', 3=>'full-duplex', default=>'-' };
}

function poeClass($v) {
    $v = intval($v);
    return match($v) { 0=>'Sınıf 0', 1=>'Sınıf 1', 2=>'Sınıf 2', 3=>'Sınıf 3', 4=>'Sınıf 4', default=>'-' };
}

try {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $switchId = intval($input['switch_id'] ?? 0);
    $portNum  = intval($input['port'] ?? 0);

    if (!$switchId || !$portNum) {
        echo json_encode(['success'=>false,'error'=>'switch_id ve port gerekli']);
        exit;
    }

    // Get switch → SNMP device credentials
    $stmt = $conn->prepare("
        SELECT s.name, s.ip, s.model, sd.ip_address, sd.snmp_version,
               sd.snmp_v3_username, sd.snmp_v3_auth_protocol,
               sd.snmp_v3_auth_password, sd.snmp_v3_priv_protocol,
               sd.snmp_v3_priv_password, sd.snmp_community,
               sd.snmp_engine_id,
               s.ports
        FROM switches s
        LEFT JOIN snmp_devices sd ON (s.name = sd.name OR s.ip = sd.ip_address)
        WHERE s.id = ?
    ");
    $stmt->bind_param('i', $switchId);
    $stmt->execute();
    $sw = $stmt->get_result()->fetch_assoc();

    if (!$sw || empty($sw['ip_address'])) {
        echo json_encode(['success'=>false,'error'=>'Bu switch için SNMP yapılandırması yok']);
        exit;
    }

    if (!extension_loaded('snmp')) {
        echo json_encode(['success'=>false,'error'=>'PHP SNMP eklentisi yüklü değil']);
        exit;
    }

    $ip = $sw['ip_address'];
    $i  = $portNum;
    $switchModel = strtolower($sw['model'] ?? $sw['name'] ?? '');

    if ($sw['snmp_version'] === '3') {
        $authProto = (strtoupper($sw['snmp_v3_auth_protocol'] ?? 'SHA') === 'MD5') ? 'MD5' : 'SHA';
        $privProto = (strtoupper($sw['snmp_v3_priv_protocol'] ?? 'AES') === 'DES') ? 'DES' : 'AES';
        $snmp = new SNMP(SNMP::VERSION_3, $ip, $sw['snmp_v3_username'] ?? 'snmpuser');
        $snmp->setSecurity('authPriv', $authProto,
            $sw['snmp_v3_auth_password'] ?? '',
            $privProto, $sw['snmp_v3_priv_password'] ?? '',
            $sw['snmp_engine_id'] ?? '', '');
    } else {
        $snmp = new SNMP(SNMP::VERSION_2c, $ip, $sw['snmp_community'] ?? 'public');
    }
    $snmp->valueretrieval = SNMP_VALUE_PLAIN;
    $snmp->quick_print = true;
    $snmp->timeout = 3000000;
    $snmp->retries = 1;

    // For Catalyst/C9200L switches (IOS-XE), ifIndex ≠ port_number.
    // CBS350 uses sequential ifIndex (1-28 = ports 1-28) so no walk needed.
    // C9200L: GigabitEthernet1/0/N can have any ifIndex assigned by firmware.
    $isModernCatalyst = (
        strpos($switchModel, 'c9200') !== false ||
        strpos($switchModel, '9200') !== false ||
        strpos($switchModel, 'c9300') !== false ||
        strpos($switchModel, '9300') !== false
    );
    if ($isModernCatalyst) {
        try {
            $ifDescrWalk = @$snmp->walk('1.3.6.1.2.1.2.2.1.2');
            if ($ifDescrWalk && is_array($ifDescrWalk)) {
                $physPorts = [];
                foreach ($ifDescrWalk as $oid => $descr) {
                    $d = parseSnmpValue($descr);
                    // Match physical data ports with positive port component (excludes GE1/0/0 and sub-ifs)
                    if (preg_match('/^(GigabitEthernet|TenGigabitEthernet|TwoGigabitEthernet)(\d+)\/(\d+)\/(\d+)$/i', $d, $m)
                        && intval($m[4]) > 0) {
                        $parts = explode('.', ltrim((string)$oid, '.'));
                        $ifIdx = intval(end($parts));
                        if ($ifIdx > 0) {
                            $physPorts[$ifIdx] = [
                                'ifName' => $d,
                                'slot'   => intval($m[2]),
                                'sub'    => intval($m[3]),
                                'port'   => intval($m[4]),
                            ];
                        }
                    }
                }
                // Sort by interface name components (slot, subslot, port) —
                // matches Python worker ordering so port_number is consistent.
                uasort($physPorts, function($a, $b) {
                    if ($a['slot'] !== $b['slot']) return $a['slot'] - $b['slot'];
                    if ($a['sub']  !== $b['sub'])  return $a['sub']  - $b['sub'];
                    return $a['port'] - $b['port'];
                });
                $portList = array_keys($physPorts);
                if (isset($portList[$portNum - 1])) {
                    $i = intval($portList[$portNum - 1]); // use actual ifIndex
                }
            }
        } catch (SNMPException $e) {
            // fall back to $portNum if walk fails
        }
    }

    // ── Temel
    $ifDescr       = parseSnmpValue(@$snmp->get("1.3.6.1.2.1.2.2.1.2.$i"));
    $ifName        = parseSnmpValue(@$snmp->get("1.3.6.1.2.1.31.1.1.1.1.$i"));
    $ifAlias       = parseSnmpValue(@$snmp->get("1.3.6.1.2.1.31.1.1.1.18.$i"));
    $ifMtu         = intval(@$snmp->get("1.3.6.1.2.1.2.2.1.4.$i"));
    $ifSpeed       = @$snmp->get("1.3.6.1.2.1.2.2.1.5.$i");
    $ifHighSpeed   = @$snmp->get("1.3.6.1.2.1.31.1.1.1.15.$i");
    $ifPhysAddress = @$snmp->get("1.3.6.1.2.1.2.2.1.6.$i");

    // ── Durum
    $ifAdminStatus = intval(@$snmp->get("1.3.6.1.2.1.2.2.1.7.$i"));
    $ifOperStatus  = intval(@$snmp->get("1.3.6.1.2.1.2.2.1.8.$i"));
    $ifLastChange  = @$snmp->get("1.3.6.1.2.1.2.2.1.9.$i");
    $dot3Duplex    = @$snmp->get("1.3.6.1.2.1.10.7.2.1.19.$i");

    // ── VLAN
    $dot1qPvid = intval(parseSnmpValue(@$snmp->get("1.3.6.1.2.1.17.7.1.4.5.1.1.$i")));
    $vmVlan    = intval(parseSnmpValue(@$snmp->get("1.3.6.1.4.1.9.9.68.1.2.2.1.2.$i")));

    // ── DB fallback: when SNMP returns nothing useful, read from port_status_data.
    // Triggered for C9200L (engine-ID auto-discovery often fails on XAMPP/Windows)
    // AND for CBS350 when SNMPv3 credentials were not yet stored in snmp_devices
    // (null auth_password causes authentication failure → all values 0/empty).
    // We check ifDescr AND ifMtu: both are always non-empty/non-zero on a
    // reachable port (MTU minimum is 64 bytes), so zero means SNMP auth failed.
    // ifPhysAddress is intentionally excluded: SFP uplinks may have no L2 address
    // yet still respond to SNMP normally, which would cause a false positive.
    $snmpFailed = empty($ifDescr) && $ifMtu === 0;

    // Always query port_status_data — it is polled by the Python worker and is
    // the same authoritative source the Port Connections tab uses to show UP/DOWN.
    $dbStmt = $conn->prepare("
        SELECT psd.*
        FROM port_status_data psd
        JOIN snmp_devices sd ON psd.device_id = sd.id
        JOIN switches s ON (s.name = sd.name OR s.ip = sd.ip_address)
        WHERE s.id = ? AND psd.port_number = ?
        ORDER BY psd.id DESC LIMIT 1
    ");
    $dbStmt->bind_param('ii', $switchId, $portNum);
    $dbStmt->execute();
    $dbRow = $dbStmt->get_result()->fetch_assoc();
    if ($dbRow) {
        if ($snmpFailed) {
            // Full fallback: SNMP is unreachable — use all fields from DB.
            $portLabel = $isModernCatalyst ? "Gi1/0/$portNum" : "GE$portNum";
            $descrLabel = $isModernCatalyst ? "GigabitEthernet1/0/$portNum" : "GE$portNum";
            $ifName        = $dbRow['port_name']  ?: $portLabel;
            $ifAlias       = $dbRow['port_alias']  ?: '';
            $ifDescr       = $dbRow['port_name']  ?: $descrLabel;
            $ifMtu         = intval($dbRow['port_mtu'] ?? 0);
            $ifSpeed       = intval($dbRow['port_speed'] ?? 0);
            $ifHighSpeed   = intval($dbRow['port_speed'] ?? 0);
            $ifHighSpeed   = $ifHighSpeed > 0 ? round($ifHighSpeed / 1000000) : 0;
            $ifPhysAddress = $dbRow['mac_address'] ?? '';
            $dot1qPvid     = intval($dbRow['vlan_id'] ?? 1);
            $inOctets      = intval($dbRow['in_octets']  ?? $dbRow['bytes_in']  ?? 0);
            $outOctets     = intval($dbRow['out_octets'] ?? $dbRow['bytes_out'] ?? 0);
            $inErrors      = intval($dbRow['in_errors']  ?? $dbRow['errors_in'] ?? 0);
            $outErrors     = intval($dbRow['out_errors'] ?? $dbRow['errors_out'] ?? 0);
        }
        // Always prefer port_status_data for admin/oper status regardless of whether
        // live SNMP is reachable. The Python worker independently polls the switch and
        // stores the correct status here — this is what the Port Connections tab uses.
        $ifAdminStatus = ($dbRow['admin_status'] === 'up') ? 1 : 2;
        $ifOperStatus  = ($dbRow['oper_status']  === 'up') ? 1 : 2;
    }

    // VLAN untagged walk (CBS350 only — bitmap approach works for sequential ifIndex)
    // C9200L: use dot1qPvid / vmVlan directly (already fetched above)
    $portVlans = []; $primaryVlan = 1;
    if ($isModernCatalyst) {
        // C9200L: bitmap port-index ≠ ifIndex, so bitmap gives wrong results.
        // Use PVID (indexed by ifIndex) or vmVlan fallback.
        if ($dot1qPvid > 1)      { $primaryVlan = $dot1qPvid; $portVlans = [$dot1qPvid]; }
        elseif ($vmVlan > 1)     { $primaryVlan = $vmVlan;    $portVlans = [$vmVlan]; }
        else                     { $portVlans = [1]; }
    } else {
        $untaggedWalk = @$snmp->walk('1.3.6.1.2.1.17.7.1.4.2.1.5');
        if ($untaggedWalk && is_array($untaggedWalk)) {
            foreach ($untaggedWalk as $oid => $mask) {
                if (!preg_match('/\.(\d+)\.(\d+)$/', $oid, $m)) continue;
                $vid = (int)$m[2];
                $bpos = (int)(($i-1)/8); $bit = 7-(($i-1)%8);
                if ($bpos < strlen($mask) && ((ord($mask[$bpos]) >> $bit) & 1)) {
                    $portVlans[] = $vid;
                    if ($vid != 1) $primaryVlan = $vid;
                }
            }
        }
    }

    // ── PoE (CBS350: ports 1-24 PoE; C9200L-48P: ports 1-48 PoE)
    $poeMaxPort = $isModernCatalyst ? 48 : 24;
    $poeEnabled = null; $poePower = null; $poeClass = null; $poePriority = null;
    if ($portNum <= $poeMaxPort && !$snmpFailed) {
        $poeEnabled  = intval(parseSnmpValue(@$snmp->get("1.3.6.1.2.1.105.1.1.1.3.$i"))) == 1;
        $poePower    = intval(@$snmp->get("1.3.6.1.2.1.105.1.1.1.7.$i"));
        $poeClass    = intval(@$snmp->get("1.3.6.1.2.1.105.1.1.1.5.$i"));
        $poePriority = intval(@$snmp->get("1.3.6.1.2.1.105.1.1.1.4.$i"));
    }

    // ── Trafik (only fetch from SNMP when SNMP is working; otherwise already set from DB)
    if (!$snmpFailed) {
        $inOctets    = intval(@$snmp->get("1.3.6.1.2.1.31.1.1.1.6.$i"));  // 64-bit
        $outOctets   = intval(@$snmp->get("1.3.6.1.2.1.31.1.1.1.10.$i")); // 64-bit
        $inUcast     = intval(@$snmp->get("1.3.6.1.2.1.2.2.1.11.$i"));
        $outUcast    = intval(@$snmp->get("1.3.6.1.2.1.2.2.1.17.$i"));
        $inErrors    = intval(@$snmp->get("1.3.6.1.2.1.2.2.1.14.$i"));
        $outErrors   = intval(@$snmp->get("1.3.6.1.2.1.2.2.1.20.$i"));
        $inDiscards  = intval(@$snmp->get("1.3.6.1.2.1.2.2.1.13.$i"));
        $outDiscards = intval(@$snmp->get("1.3.6.1.2.1.2.2.1.19.$i"));
        $fcsErrors   = intval(@$snmp->get("1.3.6.1.2.1.10.7.2.1.2.$i"));
    } else {
        // Values already loaded from DB above; set remaining to 0
        $inUcast = $outUcast = $inDiscards = $outDiscards = $fcsErrors = 0;
    }

    // ── LLDP (neighbor) — only query via SNMP when SNMP is working
    $lldpNeighbor = null;
    if (!$snmpFailed) {
        $lldpSysName = parseSnmpValue(@$snmp->get("1.0.8802.1.1.2.1.4.1.1.9.0.$i.1"));
        $lldpPortId  = parseSnmpValue(@$snmp->get("1.0.8802.1.1.2.1.4.1.1.7.0.$i.1"));
        $lldpCaps    = parseSnmpValue(@$snmp->get("1.0.8802.1.1.2.1.4.1.1.12.0.$i.1"));
        $lldpMgmtIp  = parseSnmpValue(@$snmp->get("1.0.8802.1.1.2.1.4.2.1.5.0.$i.1.4.0.0.0.0"));
        if ($lldpSysName) {
            $lldpNeighbor = ['system_name'=>$lldpSysName,'port_id'=>$lldpPortId,'capabilities'=>$lldpCaps,'mgmt_ip'=>$lldpMgmtIp];
        }
    }

    $result = [
        'success' => true,
        'switch_name' => $sw['name'],
        'port' => $i,
        'source' => $snmpFailed ? 'database' : 'snmp',
        'temel' => [
            'descr'   => $ifDescr ?: ($isModernCatalyst ? "GigabitEthernet1/0/$portNum" : "GE$portNum"),
            'name'    => $ifName  ?: ($isModernCatalyst ? "Gi1/0/$portNum" : "GE$portNum"),
            'alias'   => $ifAlias,
            'mtu'     => $ifMtu,
            'speed'   => formatSpeed($ifSpeed),
            'high_speed' => intval($ifHighSpeed) > 0 ? intval($ifHighSpeed).' Mbps' : '-',
            'mac'     => formatMac($ifPhysAddress),
        ],
        'durum' => [
            'admin'       => $ifAdminStatus == 1 ? 'up' : 'down',
            'oper'        => $ifOperStatus  == 1 ? 'up' : ($ifOperStatus == 2 ? 'down' : 'unknown'),
            'last_change' => formatUptime($ifLastChange),
            'duplex'      => duplex($dot3Duplex),
        ],
        'vlan' => [
            'primary' => $primaryVlan,
            'pvid'    => $dot1qPvid,
            'vm_vlan' => $vmVlan,
            'vlans'   => $portVlans,
        ],
        'poe' => ($portNum <= $poeMaxPort) ? [
            'enabled'    => $poeEnabled,
            'power_mw'   => $poePower,
            'power_watt' => $poePower > 0 ? round($poePower/1000,1).' W' : '-',
            'class'      => poeClass($poeClass),
            'priority'   => match($poePriority) { 1=>'critical', 2=>'high', 3=>'low', default=>'low' },
        ] : null,
        'trafik' => [
            'in_bytes'    => formatBytes($inOctets),
            'out_bytes'   => formatBytes($outOctets),
            'in_raw'      => $inOctets,
            'out_raw'     => $outOctets,
            'in_ucast'    => $inUcast,
            'out_ucast'   => $outUcast,
            'in_errors'   => $inErrors,
            'out_errors'  => $outErrors,
            'in_discards' => $inDiscards,
            'out_discards'=> $outDiscards,
            'fcs_errors'  => $fcsErrors,
        ],
        'lldp' => $lldpNeighbor,
    ];

    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_IGNORE);

} catch (Throwable $e) {
    echo json_encode(['success'=>false,'error'=>$e->getMessage()]);
}
