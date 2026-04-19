<?php
/**
 * snmp_switch_health.php — Switch düzeyinde sistem sağlık bilgileri (on-demand)
 * Kullanım: GET ?switch_id=N
 *
 * Canlı SNMP ile sistem bilgisi çeker. SNMP erişilemiyorsa (CBS350 SNMPv3 engine
 * sorunları dahil) veritabanına düşer (device_polling_data / snmp_devices).
 *
 * Döndürülen alanlar:
 *   sys_name        – cihazda kayıtlı hostname
 *   sys_uptime      – okunabilir uptime ("325g 22:45:46")
 *   uptime_raw_s    – saniye cinsinden uptime
 *   model           – model adı (CBS350-48FP-4G, C9200L-48P-4G, …)
 *   sys_descr       – tam sysDescr
 *   temperature_c   – sistem sıcaklığı °C
 *   temp_status     – "OK" / "WARNING" / "CRITICAL" / null
 *   fan_status      – "OK" / "WARNING" / "CRITICAL" / "N/A"
 *   poe_nominal_w   – nominal PoE (W), PoE yoksa null
 *   poe_consumed_w  – anlık PoE (W)
 *   poe_usage_pct   – yüzde kullanım
 *   source          – "snmp" | "database"
 */

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

// Release the PHP session lock immediately so concurrent requests (alarm poller, other
// AJAX calls) are not blocked while this script waits for SNMP responses.
session_write_close();

header('Content-Type: application/json; charset=utf-8');
header("Cache-Control: no-cache, no-store, must-revalidate");

/* ── Yardımcı fonksiyonlar ──────────────────────────────────────────────── */

function parseVal($value): string {
    if ($value === false || $value === null) return '';
    $value = trim((string)$value);
    if (preg_match('/^"(.*)"$/s', $value, $m)) return $m[1];
    if (preg_match('/^(?:STRING|INTEGER|Gauge32|Counter32|TimeTicks|IpAddress|Hex-STRING|OID|Timeticks):\s*(.+)$/s', $value, $m)) {
        $v = trim($m[1]);
        if (preg_match('/^"(.*)"$/s', $v, $m2)) return $m2[1];
        return $v;
    }
    return $value;
}

/**
 * Format uptime from raw SNMP TimeTicks (hundredths of a second) or a plain integer.
 * Both PHP SNMP and the Python worker store raw TimeTicks without conversion.
 */
function formatUptime(string $raw): array {
    if (empty($raw)) return ['text' => '-', 'seconds' => 0];
    if (preg_match('/\((\d+)\)/', $raw, $m)) $ticks = (int)$m[1];
    else $ticks = (int)$raw;
    if ($ticks <= 0) return ['text' => '-', 'seconds' => 0];
    $s = intdiv($ticks, 100);
    $d = intdiv($s, 86400); $s %= 86400;
    $h = intdiv($s, 3600);  $s %= 3600;
    $mn = intdiv($s, 60);   $s %= 60;
    $text = ($d > 0 ? "{$d}g " : '') . sprintf('%02d:%02d:%02d', $h, $mn, $s);
    return ['text' => $text, 'seconds' => intdiv($ticks, 100)];
}

/**
 * Smart model name extraction.
 *
 * Priority:
 *  1. CBS350 / known model pattern in sysDescr first token
 *     "CBS350-48FP-4G 48-Port…"  → "CBS350-48FP-4G"
 *  2. C9200L/C9300L: sysDescr starts "Cisco IOS…" — no model there.
 *     Use $dbModel from the switches table (set by admin) or snmp_devices.
 *  3. Anything else: first token.
 */
function extractModelSmart(string $descr, string $dbModel): string {
    $descr = trim($descr);
    if (empty($descr)) return $dbModel;

    // CBS350 and other SMB: first token is the model (e.g. "CBS350-48FP-4G")
    $first = strtok($descr, " \t\r\n");
    if ($first !== false && strcasecmp($first, 'cisco') !== 0) {
        return $first;
    }

    // IOS / IOS-XE: sysDescr starts with "Cisco IOS …" — model not in sysDescr.
    // Use the model stored in the switches table (set by admin or Python worker).
    if (!empty($dbModel)) {
        return $dbModel;
    }

    return ($first !== false ? $first : '') ?: $descr;
}

/** ciscoEnvMonFanState / ciscoEnvMonTemperatureState integer → label */
function envStateLabel(int $v): string {
    return match($v) {
        1 => 'OK',
        2 => 'WARNING',
        3 => 'CRITICAL',
        4 => 'SHUTDOWN',
        5, 6 => 'N/A',
        default => 'N/A',
    };
}

/* ── Giriş doğrulaması ──────────────────────────────────────────────────── */

try {
    $switchId = intval($_GET['switch_id'] ?? 0);
    if (!$switchId) {
        echo json_encode(['success' => false, 'error' => 'switch_id gerekli']);
        exit;
    }

    // Virtual switch'ler için SNMP sorgusunu atla
    $virtCheckStmt = $conn->prepare("SELECT is_virtual FROM switches WHERE id = ?");
    if ($virtCheckStmt) {
        $virtCheckStmt->bind_param('i', $switchId);
        $virtCheckStmt->execute();
        $virtRow = $virtCheckStmt->get_result()->fetch_assoc();
        $virtCheckStmt->close();
        if ($virtRow && (int)$virtRow['is_virtual'] === 1) {
            echo json_encode(['success' => false, 'virtual' => true, 'error' => 'virtual_switch']);
            exit;
        }
    }

    // Switch + SNMP kimlik bilgileri + snmp_devices'dan önbellek verileri
    // Try full query with environmental columns first; fall back without them when
    // the migration that adds fan_status/temperature_c/poe_nominal_w/poe_consumed_w
    // has not yet been applied (avoids "Sistem bilgisi alınamadı" on fresh installs).
    $sw = null;
    // Clear any lingering mysqli error state before attempting the prepared statement
    if ($conn->errno) { /* noop — just read errno to check state */ }
    $stmtFull = $conn->prepare("
        SELECT s.name, s.ip, s.model AS sw_model,
               sd.ip_address, sd.snmp_version,
               sd.snmp_v3_username, sd.snmp_v3_auth_protocol,
               sd.snmp_v3_auth_password, sd.snmp_v3_priv_protocol,
               sd.snmp_v3_priv_password, sd.snmp_community,
               sd.snmp_engine_id,
               sd.model              AS sd_model,
               sd.system_description AS sd_sys_descr,
               sd.system_uptime      AS sd_sys_uptime,
               sd.fan_status         AS sd_fan_status,
               sd.temperature_c      AS sd_temperature_c,
               sd.poe_nominal_w      AS sd_poe_nominal_w,
               sd.poe_consumed_w     AS sd_poe_consumed_w,
               sd.cpu_1min           AS sd_cpu_1min
        FROM switches s
        LEFT JOIN snmp_devices sd ON (s.name = sd.name OR s.ip = sd.ip_address)
        WHERE s.id = ?
    ");
    if ($stmtFull) {
        $stmtFull->bind_param('i', $switchId);
        if ($stmtFull->execute()) {
            $sw = $stmtFull->get_result()->fetch_assoc();
        }
    }
    // Fallback query without the environmental columns (used before migration step 52)
    if ($sw === null) {
        $stmtBasic = $conn->prepare("
            SELECT s.name, s.ip, s.model AS sw_model,
                   sd.ip_address, sd.snmp_version,
                   sd.snmp_v3_username, sd.snmp_v3_auth_protocol,
                   sd.snmp_v3_auth_password, sd.snmp_v3_priv_protocol,
                   sd.snmp_v3_priv_password, sd.snmp_community,
                   sd.snmp_engine_id,
                   sd.model              AS sd_model,
                   sd.system_description AS sd_sys_descr,
                   sd.system_uptime      AS sd_sys_uptime
            FROM switches s
            LEFT JOIN snmp_devices sd ON (s.name = sd.name OR s.ip = sd.ip_address)
            WHERE s.id = ?
        ");
        if ($stmtBasic) {
            $stmtBasic->bind_param('i', $switchId);
            if ($stmtBasic->execute()) {
                $row = $stmtBasic->get_result()->fetch_assoc();
                if ($row) {
                    // Pad with null env fields so the rest of the code can reference them safely
                    $sw = array_merge([
                        'sd_fan_status'    => null,
                        'sd_temperature_c' => null,
                        'sd_poe_nominal_w' => null,
                        'sd_poe_consumed_w'=> null,
                        'sd_cpu_1min'      => null,
                    ], $row);
                }
            }
        }
    }

    if (!$sw) {
        echo json_encode(['success' => false, 'error' => 'Switch bulunamadı']);
        exit;
    }

    // snmp_devices kaydı yoksa config.yml'den kimlik bilgisi al
    if (empty($sw['ip_address'])) {
        $creds = getSnmpCredsFromConfig($sw['ip'] ?? '');
        if ($creds) {
            $sw = array_merge($sw, $creds);
        } else {
            echo json_encode(['success' => false, 'error' => 'SNMP yapılandırması yok']);
            exit;
        }
    }

    // ── DB önbelleğinden sistem bilgisi hazırla ──────────────────────────────
    // device_polling_data: system_name, system_description, system_uptime, temperature, memory_usage
    // Also retrieve poll_timestamp to decide if cached data is fresh enough to skip
    // live SNMP (saves 3-9 seconds of latency per switch card open).
    $dbPoll = null;
    $dbPollStmt = $conn->prepare("
        SELECT dpd.system_name, dpd.system_description, dpd.system_uptime, dpd.temperature,
               dpd.memory_usage, dpd.poll_timestamp
        FROM device_polling_data dpd
        JOIN snmp_devices sd ON dpd.device_id = sd.id
        JOIN switches s ON (s.name = sd.name OR s.ip = sd.ip_address)
        WHERE s.id = ?
        ORDER BY dpd.poll_timestamp DESC
        LIMIT 1
    ");
    // Guard: prepare() returns false when a table/column is missing (e.g. on a
    // fresh install before all migrations ran).  Calling bind_param() on false
    // throws a fatal Error that the outer catch converts to success:false →
    // "Sistem bilgisi alınamadı".  Treat a failed prepare as "no cached poll data".
    if ($dbPollStmt) {
        $dbPollStmt->bind_param('i', $switchId);
        $dbPollStmt->execute();
        $dbPoll = $dbPollStmt->get_result()->fetch_assoc();
    }

    // If the Python worker polled this device within the last 3 minutes, serve from
    // the DB cache and skip the live SNMP query entirely (avoids blocking the session
    // and prevents the "Sistem bilgileri alınıyor… çok uzun sürüyor" issue).
    $dbDataFresh = false;
    if ($dbPoll && !empty($dbPoll['poll_timestamp'])) {
        $pollAge = time() - strtotime($dbPoll['poll_timestamp']);
        $dbDataFresh = ($pollAge >= 0 && $pollAge <= 180); // 3 dakika
    }

    // ── Birleştirilmiş model adı (sw_model > sd_model > sysDescr extraction) ──
    $bestDbModel = $sw['sw_model'] ?: $sw['sd_model'] ?: '';

    // CBS350 switches use CISCOSB-specific OIDs for temperature/fan data that the
    // live SNMP health queries below don't support.  The Python worker collects all
    // CBS350 environment metrics via CISCOSB-ENVMON-MIB and stores them in
    // snmp_devices / device_polling_data, so we always use the DB cache for CBS350
    // and skip the live SNMP walk entirely (avoids 3-9 s of timeouts per open).
    $sysDescrFromDb = $sw['sd_sys_descr'] ?? ($dbPoll['system_description'] ?? '');
    $isCBS350model = (
        stripos($bestDbModel,    'cbs350')  !== false ||
        stripos($bestDbModel,    'cbs-350') !== false ||
        stripos($bestDbModel,    'cbs 350') !== false ||
        stripos($sysDescrFromDb, 'cbs350')  !== false ||
        stripos($sysDescrFromDb, 'cbs-350') !== false
    );
    if ($isCBS350model) {
        $dbDataFresh = true; // force DB-only path for CBS350
    }

    /**
     * Attempt live SNMP query and return a filled data array.
     * Returns null if SNMP is unavailable or all basic OIDs fail.
     */
    $trySnmp = function() use ($sw): ?array {
        if (!extension_loaded('snmp')) return null;

        $ip = $sw['ip_address'];
        if ($sw['snmp_version'] === '3') {
            $authProto = (strtoupper($sw['snmp_v3_auth_protocol'] ?? 'SHA') === 'MD5') ? 'MD5' : 'SHA';
            $privProto = (strtoupper($sw['snmp_v3_priv_protocol'] ?? 'AES') === 'DES') ? 'DES' : 'AES';
            $snmp = new SNMP(SNMP::VERSION_3, $ip, $sw['snmp_v3_username'] ?? 'snmpuser');
            // setSecurity($sec_level, $auth_proto, $auth_pass, $priv_proto, $priv_pass, $contextName, $contextEngineID)
            // CBS350 and other Cisco switches may require the engine_id to be specified explicitly.
            // Pass '' for contextName (default context); pass the stored engine_id (hex string)
            // as contextEngineID so PHP net-snmp can authenticate without the USM discovery round-trip.
            $engineId = !empty($sw['snmp_engine_id']) ? $sw['snmp_engine_id'] : '';
            $snmp->setSecurity('authPriv', $authProto,
                $sw['snmp_v3_auth_password'] ?? '',
                $privProto, $sw['snmp_v3_priv_password'] ?? '',
                /* contextName */ '', /* contextEngineID */ $engineId);
        } else {
            $snmp = new SNMP(SNMP::VERSION_2c, $ip, $sw['snmp_community'] ?? 'public');
        }
        $snmp->valueretrieval = SNMP_VALUE_PLAIN;
        $snmp->quick_print    = true;
        $snmp->timeout        = 1500000;   // 1,500,000 µs = 1.5 s (reduced from 3,000,000 µs to keep UI responsive)
        $snmp->retries        = 1;

        /* ── Sistem OID'leri ── */
        $sysDescrRaw  = parseVal(@$snmp->get('1.3.6.1.2.1.1.1.0'));  // sysDescr

        // Early-fail: sysDescr is always non-empty on any reachable device.
        // A single timeout (1.5 s) is enough to detect auth failure; skip
        // sysName/sysUptime to avoid two more unnecessary timeouts.
        if (empty($sysDescrRaw)) return null;

        $sysNameRaw   = parseVal(@$snmp->get('1.3.6.1.2.1.1.5.0'));  // sysName
        $sysUptimeRaw = parseVal(@$snmp->get('1.3.6.1.2.1.1.3.0'));  // sysUpTime

        /* ── Sıcaklık ── */
        // Birincil: CISCO-ENVMON-MIB — tüm sıcaklık tablosunu walk et (.1 indeksi olmayabilir)
        $temperatureC = null;
        $tempState    = null;

        try {
            $tempWalk = @$snmp->walk('1.3.6.1.4.1.9.9.13.1.3.1.3'); // ciscoEnvMonTemperatureStatusValue
            if ($tempWalk && is_array($tempWalk)) {
                foreach ($tempWalk as $oid => $tVal) {
                    $t = intval(parseVal($tVal));
                    if ($t > 0 && $t < 200) {
                        $temperatureC = $t;
                        // Aynı satır için durum indeksini çıkart
                        $tIdx = '';
                        if (preg_match('/\.(\d+)$/', (string)$oid, $idxM)) $tIdx = $idxM[1];
                        $tStateVal = $tIdx !== '' ? intval(parseVal(@$snmp->get("1.3.6.1.4.1.9.9.13.1.3.1.6.$tIdx"))) : 0;
                        $tempState = envStateLabel($tStateVal ?: 1);
                        break;
                    }
                }
            }
        } catch (Throwable $ignored) {}

        // İkincil: ENTITY-SENSOR-MIB (entPhySensorType=8 → Celsius)
        if ($temperatureC === null) {
            try {
                $sensorTypes = @$snmp->walk('1.3.6.1.2.1.99.1.1.1.1'); // entPhySensorType
                if ($sensorTypes && is_array($sensorTypes)) {
                    foreach ($sensorTypes as $oid => $typeVal) {
                        if (intval(parseVal($typeVal)) === 8) { // celsius
                            $idx = intval(substr((string)$oid, strrpos((string)$oid, '.') + 1));
                            if ($idx > 0) {
                                $sv    = intval(parseVal(@$snmp->get("1.3.6.1.2.1.99.1.1.1.4.$idx")));
                                $scale = intval(parseVal(@$snmp->get("1.3.6.1.2.1.99.1.1.1.2.$idx")));
                                // SensorDataScale (RFC 3433): 9=units, 8=milli (÷1000)
                                $tempC = ($scale === 8) ? round($sv / 1000) : $sv;
                                if ($tempC > 0 && $tempC < 200) {
                                    $temperatureC = $tempC;
                                    $tempState    = 'OK';
                                    break;
                                }
                            }
                        }
                    }
                }
            } catch (Throwable $ignored) {}
        }

        /* ── Fan Durumu ── */
        // CISCO-ENVMON-MIB — tüm fan tablosunu walk et
        $fanStatus = 'N/A';
        try {
            $fanWalk = @$snmp->walk('1.3.6.1.4.1.9.9.13.1.4.1.3'); // ciscoEnvMonFanState
            if ($fanWalk && is_array($fanWalk) && !empty($fanWalk)) {
                $worst = 1;
                foreach ($fanWalk as $v) {
                    $iv = intval(parseVal($v));
                    if ($iv >= 1 && $iv <= 4 && $iv > $worst) $worst = $iv;
                }
                $fanStatus = envStateLabel($worst);
            }
        } catch (Throwable $ignored) {}

        /* ── PoE (pethMainPseTable) ── */
        $poeNominal  = null;
        $poeConsumed = null;
        $poeUsagePct = null;

        $nomVal  = intval(parseVal(@$snmp->get('1.3.6.1.2.1.105.1.3.1.2.1'))); // pethMainPseNominalPower
        $consVal = intval(parseVal(@$snmp->get('1.3.6.1.2.1.105.1.3.1.4.1'))); // pethMainPseConsumptionPower
        if ($nomVal > 0) {
            $poeNominal  = $nomVal;
            $poeConsumed = $consVal;
            $poeUsagePct = round($consVal / $nomVal * 100);
        }

        return [
            'sys_descr'     => $sysDescrRaw,
            'sys_name'      => $sysNameRaw,
            'sys_uptime'    => $sysUptimeRaw,
            'temperature_c' => $temperatureC,
            'temp_status'   => $tempState,
            'fan_status'    => $fanStatus,
            'poe_nominal'   => $poeNominal,
            'poe_consumed'  => $poeConsumed,
            'poe_usage_pct' => $poeUsagePct,
        ];
    };

    // ── 1. Canlı SNMP dene ──────────────────────────────────────────────────
    // Skip live SNMP if the Python worker cached fresh data in the last 3 minutes.
    // This prevents the UI from blocking for seconds on every switch card open.
    $snmpData = $dbDataFresh ? null : $trySnmp();

    if ($snmpData !== null) {
        // SNMP çalıştı
        $source       = 'snmp';
        $sysDescrRaw  = $snmpData['sys_descr'];
        $sysNameRaw   = $snmpData['sys_name'];
        $sysUptimeRaw = $snmpData['sys_uptime'];
        $temperatureC = $snmpData['temperature_c'];
        $tempState    = $snmpData['temp_status'];
        $fanStatus    = $snmpData['fan_status'];
        $poeNominal   = $snmpData['poe_nominal'];
        $poeConsumed  = $snmpData['poe_consumed'];
        $poeUsagePct  = $snmpData['poe_usage_pct'];
        $cpuLoad      = null;
        $memoryUsage  = null;

        // SNMP sys_name fallback: if SNMP didn't return a name, use configured switch name
        if (empty($sysNameRaw) && !empty($sw['name'])) {
            $sysNameRaw = $sw['name'];
        }
        // SNMP sıcaklık verisi gelmediyse DB'den doldur
        if ($temperatureC === null) {
            if (!empty($sw['sd_temperature_c'])) {
                $temperatureC = (float)$sw['sd_temperature_c'];
                $tempState    = 'OK';
            } elseif ($dbPoll && !empty($dbPoll['temperature'])) {
                $temperatureC = round((float)$dbPoll['temperature']);
                $tempState    = 'OK';
            }
        }
        // SNMP fan/PoE verisi gelmediyse DB'den doldur
        if ($fanStatus === 'N/A' && !empty($sw['sd_fan_status'])) {
            $fanStatus = $sw['sd_fan_status'];
        }
        if ($poeNominal === null && !empty($sw['sd_poe_nominal_w'])) {
            $poeNominal   = (int)$sw['sd_poe_nominal_w'];
            $poeConsumed  = (int)($sw['sd_poe_consumed_w'] ?? 0);
            $poeUsagePct  = $poeNominal > 0 ? round($poeConsumed / $poeNominal * 100) : 0;
        }
        // CPU: DB önbelleğinden doldur (SNMP health endpoint CPU GET yapmıyor)
        if (isset($sw['sd_cpu_1min']) && $sw['sd_cpu_1min'] !== null) {
            $cpuLoad = (int)$sw['sd_cpu_1min'];
        }
        // Memory: en son device_polling_data satırından
        if ($dbPoll && isset($dbPoll['memory_usage']) && $dbPoll['memory_usage'] !== null) {
            $memoryUsage = (float)$dbPoll['memory_usage'];
        }
    } else {
        // ── 2. DB Fallback: SNMP erişilemedi veya taze DB verisi kullanılıyor ──
        $source       = $dbDataFresh ? 'database' : 'database';
        $sysDescrRaw  = '';
        $sysNameRaw   = '';
        $sysUptimeRaw = '';
        $temperatureC = null;
        $tempState    = null;
        $fanStatus    = 'N/A';
        $poeNominal   = null;
        $poeConsumed  = null;
        $poeUsagePct  = null;
        $cpuLoad      = null;
        $memoryUsage  = null;

        if ($dbPoll) {
            $sysNameRaw   = $dbPoll['system_name']        ?? '';
            $sysDescrRaw  = $dbPoll['system_description'] ?? ($sw['sd_sys_descr'] ?? '');
            $sysUptimeRaw = (string)($dbPoll['system_uptime'] ?? $sw['sd_sys_uptime'] ?? '');
            if (!empty($dbPoll['temperature'])) {
                $temperatureC = (int)round((float)$dbPoll['temperature']);
                $tempState    = 'OK';
            }
        } elseif (!empty($sw['sd_sys_descr'])) {
            // device_polling_data henüz yok ama snmp_devices'da önbellek var
            $sysDescrRaw  = $sw['sd_sys_descr'];
            $sysUptimeRaw = (string)($sw['sd_sys_uptime'] ?? '');
        }

        // system_name fallback: switches.name when device_polling_data not yet populated
        if (empty($sysNameRaw) && !empty($sw['name'])) {
            $sysNameRaw = $sw['name'];
        }

        // snmp_devices önbelleğinden fan/sıcaklık/PoE/CPU doldur
        if (!empty($sw['sd_fan_status'])) {
            $fanStatus = $sw['sd_fan_status'];
        }
        if ($temperatureC === null && !empty($sw['sd_temperature_c'])) {
            $temperatureC = (float)$sw['sd_temperature_c'];
            $tempState    = 'OK';
        }
        if (!empty($sw['sd_poe_nominal_w'])) {
            $poeNominal  = (int)$sw['sd_poe_nominal_w'];
            $poeConsumed = (int)($sw['sd_poe_consumed_w'] ?? 0);
            $poeUsagePct = $poeNominal > 0 ? round($poeConsumed / $poeNominal * 100) : 0;
        }
        if (isset($sw['sd_cpu_1min']) && $sw['sd_cpu_1min'] !== null) {
            $cpuLoad = (int)$sw['sd_cpu_1min'];
        }
        // Memory from device_polling_data
        if ($dbPoll && isset($dbPoll['memory_usage']) && $dbPoll['memory_usage'] !== null) {
            $memoryUsage = (float)$dbPoll['memory_usage'];
        }
    }

    /* ── Model + Uptime ── */
    $modelName  = extractModelSmart($sysDescrRaw, $bestDbModel);
    $uptimeInfo = formatUptime($sysUptimeRaw);

    /* ── PoE aktif port sayacı (port_status_data tablosundan) ── */
    $poeActivePorts = null;
    $poeTotalPorts  = null;
    $poeCountStmt = $conn->prepare("
        SELECT
            COUNT(CASE WHEN psd.poe_detecting = 1 THEN 1 END)       AS poe_active,
            COUNT(CASE WHEN psd.poe_detecting IS NOT NULL THEN 1 END) AS poe_total
        FROM port_status_data psd
        JOIN snmp_devices sd ON psd.device_id = sd.id
        JOIN switches s ON (s.name = sd.name OR s.ip = sd.ip_address)
        WHERE s.id = ?
    ");
    if ($poeCountStmt) {
        $poeCountStmt->bind_param('i', $switchId);
        if ($poeCountStmt->execute()) {
            $poeCountRow = $poeCountStmt->get_result()->fetch_assoc();
            if ($poeCountRow && $poeCountRow['poe_total'] > 0) {
                $poeActivePorts = (int)$poeCountRow['poe_active'];
                $poeTotalPorts  = (int)$poeCountRow['poe_total'];
            }
        }
        $poeCountStmt->close();
    }

    $result = [
        'success'           => true,
        'source'            => $source,
        'sys_name'          => $sysNameRaw   ?: null,
        'sys_descr'         => $sysDescrRaw  ?: null,
        'model'             => $modelName    ?: null,
        'sys_uptime'        => $uptimeInfo['text'],
        'uptime_raw_s'      => $uptimeInfo['seconds'],
        'temperature_c'     => $temperatureC,
        'temp_status'       => $tempState,
        'fan_status'        => $fanStatus    ?: 'N/A',
        'poe_nominal_w'     => $poeNominal,
        'poe_consumed_w'    => $poeConsumed,
        'poe_usage_pct'     => $poeUsagePct,
        'poe_active_ports'  => $poeActivePorts,
        'poe_total_ports'   => $poeTotalPorts,
        'cpu_load'          => $cpuLoad,
        'memory_usage'      => $memoryUsage  ?? null,
    ];

    // En az bir anlamlı veri yoksa başarısız döndür.
    // sys_uptime and cpu_load are always written by the Python worker to snmp_devices
    // even when device_info SNMP polling fails for sys_descr/model; include them so
    // the health bar still renders for switches where SNMP metadata is unavailable.
    // $bestDbModel is the last resort: if the switch exists in the DB with a known
    // model (e.g. 'C9300L'), show at minimum a model badge rather than the error.
    $anyData = ($result['sys_name'] || $result['sys_descr'] || $result['model'] ||
                $result['temperature_c'] !== null || $result['poe_nominal_w'] !== null ||
                ($result['sys_uptime'] && $result['sys_uptime'] !== '-') ||
                $result['cpu_load'] !== null ||
                !empty($bestDbModel));
    if (!$anyData) {
        $result['success'] = false;
        $result['error']   = 'Switch\'e SNMP ile erişilemedi ve veritabanında sistem bilgisi yok';
    }

    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_IGNORE);

} catch (Throwable $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
