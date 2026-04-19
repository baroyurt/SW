<?php
/**
 * snmp_port_detail.php — Tek port için SNMP detay verileri
 * Kullanım: POST JSON {"switch_id": 93, "port": 20}
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

// Release PHP session lock so concurrent AJAX requests are not serialized.
session_write_close();

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

/**
 * Map a pethPsePortPowerClassifications value to a display label.
 *
 * @param int  $v          Raw SNMP integer value.
 * @param bool $rfcOffset  When false (IOS-XE / C9200/C9300): Cisco returns 0=class0,
 *                         1=class1 … 4=class4 (direct mapping, no RFC offset).
 *                         When true (CBS350, strict RFC 3621 §4.2.2): the enum is
 *                         0=classNotEvaluated, 1=class0, 2=class1, … 5=class4
 *                         (values are 1-indexed relative to the IEEE class number).
 */
function poeClass($v, bool $rfcOffset = false): string {
    $v = intval($v);
    if ($rfcOffset) {
        return match($v) { 1=>'Sınıf 0', 2=>'Sınıf 1', 3=>'Sınıf 2', 4=>'Sınıf 3', 5=>'Sınıf 4', default=>'-' };
    }
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

    // Get switch → SNMP device credentials (also fetch is_virtual for early-out)
    $stmt = $conn->prepare("
        SELECT s.name, s.ip, s.model, s.is_virtual, sd.ip_address, sd.snmp_version,
               sd.snmp_v3_username, sd.snmp_v3_auth_protocol,
               sd.snmp_v3_auth_password, sd.snmp_v3_priv_protocol,
               sd.snmp_v3_priv_password, sd.snmp_community,
               sd.snmp_engine_id,
               sd.model              AS sd_model,
               sd.system_description AS sd_sys_descr,
               s.ports
        FROM switches s
        LEFT JOIN snmp_devices sd ON (s.name = sd.name OR s.ip = sd.ip_address)
        WHERE s.id = ?
    ");
    $stmt->bind_param('i', $switchId);
    $stmt->execute();
    $sw = $stmt->get_result()->fetch_assoc();

    if (!$sw) {
        echo json_encode(['success'=>false,'error'=>'Switch bulunamadı']);
        exit;
    }

    // Virtual switches have no SNMP agent.  Return connection info from the DB
    // directly so the port detail modal shows edge-switch data without timing out.
    if ((int)($sw['is_virtual'] ?? 0) === 1) {
        $portStmt = $conn->prepare("
            SELECT p.port_no, p.oper_status, p.connection_info_preserved,
                   p.device, p.type, p.ip, p.mac,
                   CASE
                       WHEN (p.ip IS NOT NULL AND p.ip != '')
                         OR (p.mac IS NOT NULL AND p.mac != '')
                         OR (p.device IS NOT NULL AND p.device != '' AND p.device != 'BOŞ')
                         OR (p.connection_info IS NOT NULL AND p.connection_info != '')
                       THEN 1 ELSE 0
                   END as is_active
            FROM   ports p
            WHERE  p.switch_id = ? AND p.port_no = ?
            LIMIT 1
        ");
        $portInfo = null;
        if ($portStmt) {
            $portStmt->bind_param('ii', $switchId, $portNum);
            $portStmt->execute();
            $portInfo = $portStmt->get_result()->fetch_assoc();
            $portStmt->close();
        }
        $ciRaw = $portInfo['connection_info_preserved'] ?? '';
        $ci    = json_decode($ciRaw ?: '{}', true) ?: [];
        $operStatus = $portInfo['oper_status'] ?? 'unknown';
        $isActive   = (int)($portInfo['is_active'] ?? 0);
        // When the port has a device connection but oper_status says 'down' or
        // 'unknown' (virtual switches are not SNMP-polled so the field is stale),
        // override to 'up' so the modal shows "Aktif" instead of "Bağlantı Yok".
        if ($isActive && $operStatus !== 'up') {
            $operStatus = 'up';
        }
        echo json_encode([
            'success' => true,
            'virtual' => true,
            'durum'   => ['admin' => 'up', 'oper' => $operStatus],
            'connection_info' => $ci,
            'port_no' => $portNum,
            'device'  => $portInfo['device'] ?? '',
            'type'    => $portInfo['type']   ?? '',
            'ip'      => $portInfo['ip']     ?? '',
            'mac'     => $portInfo['mac']    ?? '',
        ]);
        exit;
    }

    // When snmp_devices has no row, fall back to config.yml credentials.
    // This handles the case where the switch was manually added to the UI
    // before the Python worker ran (so snmp_devices is empty for this switch).
    if (empty($sw['ip_address'])) {
        $creds = getSnmpCredsFromConfig($sw['ip'] ?? '');
        if ($creds) {
            $sw = array_merge($sw, $creds);
        } else {
            echo json_encode(['success'=>false,'error'=>'Bu switch için SNMP yapılandırması yok']);
            exit;
        }
    }

    // When the PHP SNMP extension is disabled (e.g. to avoid the OPcache/JIT crash
    // on Windows with php_snmp.dll), skip live SNMP entirely and serve all port
    // data from the Python worker's port_status_data DB cache instead.
    $snmpExtAvailable = extension_loaded('snmp');

    $ip = $sw['ip_address'];
    $i  = $portNum;
    // Use switches.model first, then fall back to the model stored by the Python
    // worker in snmp_devices.model, then fall back to the switch name.  This ensures
    // CBS350 detection works even when the user has not set a model in the switches
    // table (e.g. after deleting and re-adding the SNMP device entry).
    $switchModel = strtolower($sw['model'] ?: $sw['sd_model'] ?: $sw['name'] ?: '');
    $sysDescrDb  = strtolower($sw['sd_sys_descr'] ?? '');

    // Model detection must happen before the SNMP object is created so the guard
    // block below can reference $isModernCatalyst / $isCBS350 even when the
    // extension is absent.
    // For Catalyst/C9200L switches (IOS-XE), ifIndex ≠ port_number.
    // CBS350 uses sequential ifIndex (1-28 = ports 1-28) so no walk needed.
    // C9200L: GigabitEthernet1/0/N can have any ifIndex assigned by firmware.
    $isModernCatalyst = (
        strpos($switchModel, 'c9200') !== false ||
        strpos($switchModel, '9200') !== false ||
        strpos($switchModel, 'c9300') !== false ||
        strpos($switchModel, '9300') !== false
    );
    // CBS350 is a standalone-OS switch; it does not support Cisco IOS-specific MIBs
    // such as CISCO-VLAN-MEMBERSHIP-MIB (vmVlan). Querying those OIDs causes a
    // 3-second timeout per OID and adds ~9 s of latency per port detail open.
    // Detection is based on switches.model first, then snmp_devices.model (sd_model),
    // then snmp_devices.system_description (sd_sys_descr) — so CBS350 is identified
    // correctly even when the user hasn't set a model in the switches table.
    $isCBS350 = (
        strpos($switchModel, 'cbs350')  !== false ||
        strpos($switchModel, 'cbs-350') !== false ||
        strpos($switchModel, 'cbs 350') !== false ||
        strpos($sysDescrDb,  'cbs350')  !== false ||
        strpos($sysDescrDb,  'cbs-350') !== false
    );

    // Only create the SNMP session object when the extension is loaded.
    // When unavailable, $snmpFailed is forced true (set below) so the existing
    // DB-fallback path fills in all values from port_status_data.
    if ($snmpExtAvailable) {
        if ($sw['snmp_version'] === '3') {
            $authProto = (strtoupper($sw['snmp_v3_auth_protocol'] ?? 'SHA') === 'MD5') ? 'MD5' : 'SHA';
            $privProto = (strtoupper($sw['snmp_v3_priv_protocol'] ?? 'AES') === 'DES') ? 'DES' : 'AES';
            $snmp = new SNMP(SNMP::VERSION_3, $ip, $sw['snmp_v3_username'] ?? 'snmpuser');
            // setSecurity order: sec_level, auth_proto, auth_pass, priv_proto, priv_pass, contextName, contextEngineID
            // CBS350 requires the engine_id as contextEngineID (7th param); contextName is '' (6th param).
            $snmp->setSecurity('authPriv', $authProto,
                $sw['snmp_v3_auth_password'] ?? '',
                $privProto, $sw['snmp_v3_priv_password'] ?? '',
                /* contextName */ '', /* contextEngineID */ $sw['snmp_engine_id'] ?? '');
        } else {
            $snmp = new SNMP(SNMP::VERSION_2c, $ip, $sw['snmp_community'] ?? 'public');
        }
        $snmp->valueretrieval = SNMP_VALUE_PLAIN;
        $snmp->quick_print = true;
        $snmp->timeout = 1500000;  // 1,500,000 µs = 1.5 s
        $snmp->retries = 1;

        // CBS350 SNMP can be slow per-OID; reduce timeout/retries to keep total latency acceptable.
        // With ~25 OIDs × 0.8s the worst-case is ~20s; typical case is ~2-3s.
        if ($isCBS350) {
            $snmp->timeout = 800000; // 0.8 s per OID — halves per-timeout wait
            $snmp->retries = 0;      // no retry — fast-fail on unresponsive OID
        }
        // Track whether the walk successfully mapped portNum to a real ifIndex.
        // Used below to force DB fallback when the mapping cannot be established.
        $catalystPortMapped = false;
        if ($isModernCatalyst) {
            try {
                $ifDescrWalk = @$snmp->walk('1.3.6.1.2.1.2.2.1.2');
                if ($ifDescrWalk && is_array($ifDescrWalk)) {
                    $physPorts = [];
                    foreach ($ifDescrWalk as $oid => $descr) {
                        $d = parseSnmpValue($descr);
                        // Match physical data ports with positive port component (excludes GE1/0/0 and sub-ifs)
                        if (preg_match('/^(GigabitEthernet|TenGigabitEthernet|TwoGigabitEthernet)(\\d+)\/(\\d+)\/(\\d+)$/i', $d, $m)
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
                        $catalystPortMapped = true;
                    }
                }
            } catch (SNMPException $e) {
                // walk failed — $catalystPortMapped stays false → DB fallback below
            }
        }
    }  // end if ($snmpExtAvailable)

    // ── Temel (probe first — if ifDescr returns empty, SNMP auth has failed)
    // Fetch the first OID only; if it fails skip all remaining GETs and fall back
    // to the DB cache immediately.  Without this guard each of the ~13 OIDs would
    // wait for the full 1.5 s timeout → ~20 s hang on every failed CBS350 request.
    //
    // CBS350 SNMPv3 fast path: when the engine_id is not yet stored in snmp_devices
    // the PHP SNMP extension must perform a USM engine-ID discovery round-trip before
    // the first OID can be fetched.  This discovery takes 5-10 s and can leave the
    // PHP SNMP session in a broken state on subsequent requests.  Skip live SNMP
    // entirely for such CBS350 devices and use the DB cache (the Python worker
    // already polls CBS350 on a regular schedule and stores all port data).
    //
    // C9200/C9300 walk fast path: on IOS-XE the ifIndex values are NOT sequential
    // and do NOT match the UI port number.  Even when the walk succeeds and maps
    // portNum → ifIndex, a live ifOperStatus GET can return DOWN for an AP port
    // that is momentarily in power-save / link-negotiation state.  The Python worker
    // polls on a regular schedule, stores reliable status in port_status_data, and
    // applies the MAC-based UP override.  Always use DB fallback for C9200/C9300.
    $snmpFailed = !$snmpExtAvailable
        || ($isCBS350 && $sw['snmp_version'] === '3' && empty($sw['snmp_engine_id']))
        || $isModernCatalyst;

    if (!$snmpFailed) {
        $ifDescr = parseSnmpValue(@$snmp->get("1.3.6.1.2.1.2.2.1.2.$i"));

        // Early-fail: if ifDescr is empty the switch is unreachable or auth failed.
        // Skip all further SNMP GET calls and let the DB fallback fill in the values.
        $snmpFailed = empty($ifDescr);
    } else {
        $ifDescr = '';
    }

    $ifName = $ifMtu = $ifSpeed = $ifHighSpeed = $ifPhysAddress = null;
    $ifAdminStatus = $ifOperStatus = 0;
    $ifLastChange  = $dot3Duplex   = null;
    $dot1qPvid     = $vmVlan       = 0;

    if (!$snmpFailed) {
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
        // vmVlan is from CISCO-VLAN-MEMBERSHIP-MIB — only supported on IOS-based Catalyst
        // switches, NOT on CBS350 (standalone OS). Querying it on CBS350 causes a 3s timeout.
        $vmVlan = (!$isCBS350)
            ? intval(parseSnmpValue(@$snmp->get("1.3.6.1.4.1.9.9.68.1.2.2.1.2.$i")))
            : 0;
    } else {
        $ifAlias = '';
    }

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
        } elseif (empty($ifAlias) && !empty($dbRow['port_alias'])) {
            // SNMP succeeded but returned empty ifAlias — use the DB-cached alias
            // (the Python worker stores port_alias from a regular SNMP walk).
            $ifAlias = trim($dbRow['port_alias']);
        }
        // For C9300L/C9200L: ifPhysAddress returns the switch port's own hardware MAC,
        // not the connected device's MAC. Always prefer port_status_data.mac_address
        // (collected from the FDB table by the Python worker) when available.
        $dbMac = !empty($dbRow['mac_address']) ? $dbRow['mac_address'] : '';
        if ($dbMac) {
            $ifPhysAddress = $dbMac;
        }
        // When live SNMP is unreachable fall back to DB admin/oper status.
        // When SNMP is working the values fetched above are the current truth;
        // the DB may be stale from the last worker poll cycle.
        // Map 'up'→1, 'down'→2, anything else ('unknown', 'dormant', …)→4 so that
        // the durum result below renders as 'unknown' rather than 'down'.
        if ($snmpFailed) {
            $ifAdminStatus = ($dbRow['admin_status'] === 'up') ? 1 : (($dbRow['admin_status'] === 'unknown') ? 4 : 2);
            $ifOperStatus  = ($dbRow['oper_status']  === 'up') ? 1 : (($dbRow['oper_status']  === 'unknown') ? 4 : 2);

            // CBS350 quirk: the firmware sometimes reports oper_status=down via SNMP
            // for ports that are physically UP and passing traffic.  The Python worker
            // stores admin_status='down' for CBS350 ports whose ifAdminStatus OID is not
            // returned (maps 'unknown' → 'down').  When port_status_data has a MAC address
            // (i.e. the FDB table had an active entry for this port on the last poll),
            // the device IS connected — override the stale DOWN status to UP.
            // The same logic applies to C9200/C9300: if the FDB returned a MAC for this
            // port at the last worker poll the port was UP.  oper_status='unknown' or a
            // stale 'down' in port_status_data should not override that evidence.
            if (($isCBS350 || $isModernCatalyst) && !empty($dbRow['mac_address']) && $ifOperStatus !== 1) {
                $ifOperStatus  = 1; // port has active device → UP
                $ifAdminStatus = 1; // admin UP
            }
            // Secondary fallback: when port_status_data oper_status is 'unknown' (e.g.
            // port was not reached during the last worker poll), consult ports.oper_status
            // which is maintained by autosync_service and always holds 'up' or 'down'.
            // This ensures C9200/C9300 and other switch types show the correct badge.
            if ($ifOperStatus !== 1 && $ifOperStatus !== 2) {
                $portsFallbackStmt = $conn->prepare(
                    "SELECT oper_status FROM ports WHERE switch_id = ? AND port_no = ? LIMIT 1"
                );
                if ($portsFallbackStmt) {
                    $portsFallbackStmt->bind_param('ii', $switchId, $portNum);
                    $portsFallbackStmt->execute();
                    $portsFallbackRow = $portsFallbackStmt->get_result()->fetch_assoc();
                    $portsFallbackStmt->close();
                    if ($portsFallbackRow) {
                        $pfOper = $portsFallbackRow['oper_status'] ?? 'unknown';
                        if ($pfOper === 'up') {
                            $ifOperStatus  = 1;
                            $ifAdminStatus = 1;
                        } elseif ($pfOper === 'down') {
                            $ifOperStatus  = 2;
                            $ifAdminStatus = 2;
                        }
                    }
                }
            }
        }
    } elseif ($snmpFailed) {
        // No port_status_data row found — fall back to ports.oper_status which is
        // maintained by autosync_service (always 'up' or 'down', never 'unknown').
        // Applies to all switch types, not just CBS350, so that C9200/C9300 ports
        // also show the correct UP/DOWN badge when port_status_data is absent.
        $portFallbackStmt = $conn->prepare(
            "SELECT oper_status FROM ports WHERE switch_id = ? AND port_no = ? LIMIT 1"
        );
        if ($portFallbackStmt) {
            $portFallbackStmt->bind_param('ii', $switchId, $portNum);
            $portFallbackStmt->execute();
            $portFallbackRow = $portFallbackStmt->get_result()->fetch_assoc();
            $portFallbackStmt->close();
            if ($portFallbackRow) {
                $fallbackOper = $portFallbackRow['oper_status'] ?? 'unknown';
                $ifOperStatus  = ($fallbackOper === 'up') ? 1 : (($fallbackOper === 'unknown') ? 4 : 2);
                $ifAdminStatus = $ifOperStatus === 1 ? 1 : 2;
            }
        }
    }

    // VLAN untagged walk (non-Catalyst only — bitmap approach works for sequential ifIndex)
    // C9200L: use dot1qPvid / vmVlan directly (already fetched above)
    // CBS350: skip the VLAN walk to prevent slow queries; dot1qPvid from SNMP or DB is enough.
    $portVlans = []; $primaryVlan = 1;
    if ($isModernCatalyst) {
        // C9200L/C9300L: bitmap port-index ≠ ifIndex, so bitmap gives wrong results.
        // Use PVID (indexed by ifIndex) or vmVlan; DB fallback is handled below.
        if ($dot1qPvid > 1) { $primaryVlan = $dot1qPvid; $portVlans = [$dot1qPvid]; }
        elseif ($vmVlan > 1){ $primaryVlan = $vmVlan;    $portVlans = [$vmVlan]; }
    } elseif (!$snmpFailed && !$isCBS350) {
        // Skip VLAN walk when SNMP auth failed or for CBS350 (walk can be very slow
        // on CBS350 due to large VLAN tables; the DB fallback below gives accurate results).
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
    } elseif ($isCBS350 && !$snmpFailed && $dot1qPvid > 1) {
        // CBS350 with working SNMP: use the already-fetched dot1qPvid (no walk needed).
        $primaryVlan = $dot1qPvid;
        $portVlans   = [$dot1qPvid];
    }
    // Universal DB VLAN fallback: when no VLAN was determined from live SNMP
    // (either SNMP failed or all VLAN OIDs returned ≤1), use the value the Python
    // worker stored — this covers CBS350 SNMP-fail path and any C9x00L edge case.
    if (empty($portVlans) || $primaryVlan <= 1) {
        $dbVlan = isset($dbRow['vlan_id']) ? intval($dbRow['vlan_id']) : 0;
        if ($dbVlan > 1) { $primaryVlan = $dbVlan; $portVlans = [$dbVlan]; }
        elseif (empty($portVlans)) { $portVlans = [1]; }
    }

    // ── PoE (CBS350: ports 1-48 PoE on -48FP/-48P, 24 on -24FP/-24P; C9200L-48P: ports 1-48 PoE)
    // Detect CBS350 PoE port count from model string (48FP/48P → 48, default 24).
    $poeMaxPort = $isModernCatalyst ? 48 : (
        (preg_match('/cbs350-48/i', $switchModel) || preg_match('/cbs350-48/i', $sysDescrDb))
        ? 48 : 24
    );
    $poeEnabled    = null; $poePower = null; $poeClass = null; $poePriority = null; $poeFault = false;
    $poeRfcOffset  = false; // whether to apply RFC3621 enum offset in poeClass()
    if ($portNum <= $poeMaxPort && !$snmpFailed) {
        // pethPsePortTable is indexed by {GroupIndex}.{PortIndex} for both device families.
        // GroupIndex is always 1 (single PSE module); PortIndex = sequential port number.
        $poeIdx = "1.$portNum";
        if ($isModernCatalyst) {
            // C9300L/C9200L: pethPsePortDetectStatus (.6): 3=deliveringPower
            // pethPsePortPowerConsumption (.10): milliwatts per RFC 3621 UNITS definition.
            // pethPsePortPowerClassifications (.7): Cisco returns 0=class0 … 4=class4 (no RFC offset)
            $poeDetect  = intval(parseSnmpValue(@$snmp->get("1.3.6.1.2.1.105.1.1.1.6.$poeIdx")));
            $poeEnabled = ($poeDetect === 3); // 3 = deliveringPower
            $rawMw      = intval(parseSnmpValue(@$snmp->get("1.3.6.1.2.1.105.1.1.1.10.$poeIdx")));
            $poePower   = $rawMw > 0 ? $rawMw : 0;  // already milliwatts per RFC 3621
            $poeClass   = intval(parseSnmpValue(@$snmp->get("1.3.6.1.2.1.105.1.1.1.7.$poeIdx")));
            $poePriority = null; // not exposed per-port via RFC3621 on IOS-XE
        } else {
            // CBS350: pethPsePortTable is indexed {GroupIndex=1}.{PortIndex=portNum}.
            // Previously this used plain $i (= portNum) which produced an OID like
            // .3.18 (GroupIndex=18, non-existent) instead of .3.1.18 — all GETs silently
            // returned null, causing "Pasif" / "Sınıf 0" for every port.
            //
            // pethPsePortPowerConsumption (.10, RFC 3621) is NOT implemented on CBS350
            // and always returns 0.  Use rlPoePsePortConsumptionPower from CISCO-SB-POE-MIB
            // (1.3.6.1.4.1.9.6.1.108.1.1.15.1.{portNum}) which returns milliwatts directly.
            // Full OID structure: rlPoe.rlPoePsePortTable.rlPoePsePortEntry.column15.{group}.{port}
            //
            // OID column reference (RFC 3621):
            //   .3  = pethPsePortAdminEnable        (1=true / 2=false)
            //   .6  = pethPsePortDetectStatus        (3=deliveringPower, 4=fault, 6=otherFault)
            //   .7  = pethPsePortPowerClassifications (RFC: 0=notEval,1=class0…5=class4)
            $poeDetect  = intval(parseSnmpValue(@$snmp->get("1.3.6.1.2.1.105.1.1.1.6.$poeIdx")));
            $poeFault   = in_array($poeDetect, [4, 6]); // 4=fault, 6=otherFault
            $poeEnabled = ($poeDetect === 3); // 3 = deliveringPower
            $rawMw      = intval(parseSnmpValue(@$snmp->get("1.3.6.1.4.1.9.6.1.108.1.1.15.1.$portNum")));
            $poePower   = $rawMw > 0 ? $rawMw : 0; // rlPoePsePortConsumptionPower returns milliwatts directly
            $poeClass   = intval(parseSnmpValue(@$snmp->get("1.3.6.1.2.1.105.1.1.1.7.$poeIdx")));
            $poeRfcOffset = true; // CBS350 returns RFC3621 enum values (1=class0…5=class4)
            $poePriority  = null; // pethPsePortPowerPriority is not in RFC3621
        }
    } elseif ($portNum <= $poeMaxPort && $snmpFailed && isset($dbRow)) {
        // DB fallback: snmp_worker polls per-port PoE via pethPsePortTable and
        // stores the result in port_status_data.poe_detecting / poe_power_mw / poe_class.
        // Use those cached values so the PoE tab shows real data even without live SNMP.
        if (array_key_exists('poe_detecting', $dbRow) && $dbRow['poe_detecting'] !== null) {
            $poeEnabled   = (bool)(int)$dbRow['poe_detecting'];
            $rawPoeMw     = intval($dbRow['poe_power_mw'] ?? 0);
            // poe_power_mw = -1 is a fault sentinel set by the CBS350 mapper
            // when pethPsePortDetectStatus returns 4 (fault) or 6 (otherFault).
            $poeFault     = ($rawPoeMw < 0);
            $poePower     = $poeFault ? 0 : $rawPoeMw;
            $poeClass     = $dbRow['poe_class'] !== null ? intval($dbRow['poe_class']) : null;
            $poeRfcOffset = !$isModernCatalyst; // CBS350 stores RFC3621 enum; C9200 stores Cisco enum
            $poePriority  = null;
        }
        // If poe_detecting column is NULL (column not yet in DB or port not PoE capable),
        // $poeEnabled remains null → result['poe'] will have no_data=true (see below).
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
        // Use SNMP walk over the lldpRemSysName subtree instead of direct GET so
        // that non-zero timeMark values (used by CBS350 and some other devices)
        // are handled correctly.  A direct GET with timeMark=0 fails on CBS350
        // fiber/SFP+ ports when the agent stores entries with timeMark > 0.
        $lldpSysName    = '';
        $lldpPortId     = '';
        $lldpCaps       = '';
        $lldpMgmtIp     = '';
        $lldpFoundTm    = 0;   // timeMark of the entry we found
        $lldpFoundRi    = 1;   // remoteIndex of the entry we found

        // Walk lldpRemSysName (.9) — find entry for local port $i
        $sysNameWalk = @$snmp->walk('1.0.8802.1.1.2.1.4.1.1.9');
        if (is_array($sysNameWalk)) {
            foreach ($sysNameWalk as $oid => $val) {
                $parts = explode('.', ltrim((string)$oid, '.'));
                // OID suffix: ...timeMark.localPort.remIndex
                if (count($parts) >= 3 && (int)$parts[count($parts)-2] === $i) {
                    $v = parseSnmpValue($val);
                    if ($v) {
                        $lldpSysName = $v;
                        $lldpFoundTm = (int)$parts[count($parts)-3];
                        $lldpFoundRi = (int)$parts[count($parts)-1];
                        break;
                    }
                }
            }
        }

        // Fallback: lldpRemSysDesc (.10) when sysName is absent
        if (!$lldpSysName) {
            $sysDescWalk = @$snmp->walk('1.0.8802.1.1.2.1.4.1.1.10');
            if (is_array($sysDescWalk)) {
                foreach ($sysDescWalk as $oid => $val) {
                    $parts = explode('.', ltrim((string)$oid, '.'));
                    if (count($parts) >= 3 && (int)$parts[count($parts)-2] === $i) {
                        $v = parseSnmpValue($val);
                        if ($v) {
                            $lldpSysName = $v;
                            $lldpFoundTm = (int)$parts[count($parts)-3];
                            $lldpFoundRi = (int)$parts[count($parts)-1];
                            break;
                        }
                    }
                }
            }
        }

        // Fetch portId (.7), portDesc (.8), capabilities (.12) using the exact
        // timeMark + remoteIndex discovered above (or timeMark=0 if nothing found)
        $lldpPortId = parseSnmpValue(@$snmp->get("1.0.8802.1.1.2.1.4.1.1.7.$lldpFoundTm.$i.$lldpFoundRi"));
        if (!$lldpPortId) {
            $lldpPortId = parseSnmpValue(@$snmp->get("1.0.8802.1.1.2.1.4.1.1.8.$lldpFoundTm.$i.$lldpFoundRi"));
        }
        $lldpCaps   = parseSnmpValue(@$snmp->get("1.0.8802.1.1.2.1.4.1.1.12.$lldpFoundTm.$i.$lldpFoundRi"));
        $lldpMgmtIp = parseSnmpValue(@$snmp->get("1.0.8802.1.1.2.1.4.2.1.5.$lldpFoundTm.$i.$lldpFoundRi.1.4.0.0.0.0"));
        // Populate $lldpNeighbor when ANY useful LLDP data is available.
        // Some device pairs only advertise lldpRemPortDesc without lldpRemSysName
        // (e.g. CBS350 ↔ Catalyst 9606), so do NOT gate on $lldpSysName alone.
        if ($lldpSysName || $lldpPortId) {
            $lldpNeighbor = ['system_name'=>$lldpSysName,'port_id'=>$lldpPortId,'capabilities'=>$lldpCaps,'mgmt_ip'=>$lldpMgmtIp];

            // ── Persist LLDP neighbor data when it mentions a core switch ─────
            // This ensures connection_info_preserved is kept fresh for
            // sync_core_ports.php even between Python worker runs.
            // Also resolve the CORESW name from management IP when sysName is absent.
            $resolvedSysName = $lldpSysName;
            if (!$resolvedSysName && $lldpMgmtIp) {
                // Try to identify the remote switch from its management IP
                $ipStmt = $conn->prepare(
                    "SELECT s.name FROM switches s
                     JOIN snmp_devices sd ON (sd.name = s.name OR sd.ip_address = s.ip)
                     WHERE s.is_core = 1 AND LEFT(s.name,1) != '{'
                       AND sd.ip_address = ?
                     LIMIT 1"
                );
                if ($ipStmt) {
                    $ipStmt->bind_param('s', $lldpMgmtIp);
                    $ipStmt->execute();
                    $ipRow = $ipStmt->get_result()->fetch_assoc();
                    $ipStmt->close();
                    if ($ipRow) {
                        $resolvedSysName = $ipRow['name'];
                        // Update $lldpNeighbor with the resolved name for UI display
                        $lldpNeighbor['system_name'] = $resolvedSysName;
                    }
                }
            }
            if ($resolvedSysName && stripos($resolvedSysName, 'CORESW') !== false) {
                $rawLldp = trim($resolvedSysName . ($lldpPortId ? ' | ' . $lldpPortId : ''));
                // Always refresh: write raw LLDP text so sync_core_ports.php
                // can recreate the virtual_core JSON on its next run
                $ciStmt = $conn->prepare(
                    "SELECT p.id, p.connection_info_preserved
                     FROM ports p
                     JOIN switches s ON s.id = p.switch_id
                     WHERE s.id = ? AND p.port_no = ?
                     LIMIT 1"
                );
                if ($ciStmt) {
                    $ciStmt->bind_param('ii', $switchId, $portNum);
                    $ciStmt->execute();
                    $ciRow = $ciStmt->get_result()->fetch_assoc();
                    $ciStmt->close();
                    if ($ciRow) {
                        $updStmt = $conn->prepare(
                            "UPDATE ports SET connection_info_preserved = ? WHERE id = ?"
                        );
                        if ($updStmt) {
                            $updStmt->bind_param('si', $rawLldp, $ciRow['id']);
                            $updStmt->execute();
                            $updStmt->close();
                        }
                    }
                }
            }
        }
    }

    // ── LLDP DB fallback ──────────────────────────────────────────────────────
    // When live SNMP found no LLDP neighbor (either SNMP failed entirely or the
    // walk returned no entry for this local port), fall back to the raw_lldp
    // string stored inside connection_info_preserved by the Python worker.
    // This covers C9200/C9300 fiber uplink ports whose SNMP lldpRemTable may
    // not be reachable from the web server, but whose raw_lldp was written by
    // the background autosync worker.
    if ($lldpNeighbor === null) {
        $lldpDbStmt = $conn->prepare(
            "SELECT p.connection_info_preserved FROM ports p
             WHERE  p.switch_id = ? AND p.port_no = ? LIMIT 1"
        );
        if ($lldpDbStmt) {
            $lldpDbStmt->bind_param('ii', $switchId, $portNum);
            $lldpDbStmt->execute();
            $lldpDbRow = $lldpDbStmt->get_result()->fetch_assoc();
            $lldpDbStmt->close();
            if ($lldpDbRow && !empty($lldpDbRow['connection_info_preserved'])) {
                $lldpCiParsed = json_decode($lldpDbRow['connection_info_preserved'], true);
                $rawLldpStr = is_array($lldpCiParsed) ? trim($lldpCiParsed['raw_lldp'] ?? '') : '';
                if ($rawLldpStr === '' && is_array($lldpCiParsed)) {
                    // Synthesise raw_lldp from core switch name + port label when it was not
                    // populated yet (worker cycle has not run since the last fix).
                    $cswName   = trim($lldpCiParsed['core_switch_name'] ?? '');
                    $cswLabel  = trim($lldpCiParsed['core_port_label']  ?? '');
                    if ($cswName) {
                        $rawLldpStr = $cswLabel ? "$cswName | $cswLabel" : $cswName;
                    }
                }
                if ($rawLldpStr !== '') {
                    // "SysName | PortId" format written by autosync_service
                    $lldpDbParts = array_map('trim', explode('|', $rawLldpStr, 2));
                    $lldpNeighbor = [
                        'system_name'  => $lldpDbParts[0] ?? '',
                        'port_id'      => $lldpDbParts[1] ?? '',
                        'capabilities' => '',
                        'mgmt_ip'      => '',
                        'source'       => 'db',
                    ];
                }
            }
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
            'fdb_mac' => isset($dbRow) ? (formatMac($dbRow['mac_address'] ?? '') ?: '') : '',
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
        // PoE: show real data when either live SNMP worked OR the DB cache has per-port PoE.
        // $poeEnabled is non-null in both cases. When SNMP failed and DB has no PoE columns
        // (migration not yet run), $poeEnabled stays null → return no_data flag to the UI.
        'poe' => ($portNum <= $poeMaxPort) ? (
            $poeEnabled !== null
                ? [
                    'enabled'    => $poeEnabled,
                    'fault'      => $poeFault,
                    'power_mw'   => $poePower,
                    'power_watt' => $poePower > 0 ? round($poePower/1000,1).' W' : '-',
                    'class'      => poeClass($poeClass, $poeRfcOffset),
                    'priority'   => match($poePriority) { 1=>'critical', 2=>'high', 3=>'low', default=>'low' },
                ]
                : ['no_data' => true]
        ) : null,
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
