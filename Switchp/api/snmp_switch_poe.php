<?php
/**
 * snmp_switch_poe.php — Switch düzeyinde PoE güç bütçesi
 * Kullanım: GET ?switch_id=93
 *
 * Strateji (snmp_switch_health.php ile aynı yaklaşım):
 *  1. snmp_devices tablosundan Python worker'ın önbelleğe aldığı poe_nominal_w /
 *     poe_consumed_w değerlerini oku (CBS350 ve C9300 her ikisi de
 *     pethMainPseTable'ı — RFC 3621 — kullanır, Python worker zaten saklıyor).
 *  2. DB değerleri NULL ise canlı SNMP walk yap: sabit .1 indeksi yerine tüm
 *     pethMainPseNominalPower tablosunu walk ederek herhangi bir modül indeksini
 *     (CBS350 stack modunda .1 dışında olabilir) otomatik bul.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

// Release the PHP session lock so SNMP queries here do not block other concurrent requests.
session_write_close();

header('Content-Type: application/json; charset=utf-8');
header("Cache-Control: no-cache, no-store, must-revalidate");

// Strip type-prefix from PHP SNMP plain values (e.g. "INTEGER: 370" → "370").
function poeParseVal(mixed $v): string {
    $s = (string)$v;
    if (str_contains($s, ':')) {
        $s = trim(substr($s, strpos($s, ':') + 1));
    }
    return $s;
}

try {
    $switchId = intval($_GET['switch_id'] ?? 0);
    if (!$switchId) {
        echo json_encode(['success' => false, 'error' => 'switch_id gerekli']);
        exit;
    }

    // ── 1. DB-first: Python worker'ın sakladığı PoE verisi ──────────────────
    $sw = null;
    $stmtFull = $conn->prepare("
        SELECT s.name, s.ip, s.model,
               sd.ip_address, sd.snmp_version,
               sd.snmp_v3_username, sd.snmp_v3_auth_protocol,
               sd.snmp_v3_auth_password, sd.snmp_v3_priv_protocol,
               sd.snmp_v3_priv_password, sd.snmp_community,
               sd.snmp_engine_id,
               sd.poe_nominal_w  AS db_poe_nominal_w,
               sd.poe_consumed_w AS db_poe_consumed_w
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
    // Fallback query without poe columns (pre-migration installs)
    if ($sw === null) {
        $stmtBasic = $conn->prepare("
            SELECT s.name, s.ip, s.model,
                   sd.ip_address, sd.snmp_version,
                   sd.snmp_v3_username, sd.snmp_v3_auth_protocol,
                   sd.snmp_v3_auth_password, sd.snmp_v3_priv_protocol,
                   sd.snmp_v3_priv_password, sd.snmp_community,
                   sd.snmp_engine_id
            FROM switches s
            LEFT JOIN snmp_devices sd ON (s.name = sd.name OR s.ip = sd.ip_address)
            WHERE s.id = ?
        ");
        if ($stmtBasic) {
            $stmtBasic->bind_param('i', $switchId);
            if ($stmtBasic->execute()) {
                $row = $stmtBasic->get_result()->fetch_assoc();
                if ($row) {
                    $sw = array_merge(['db_poe_nominal_w' => null, 'db_poe_consumed_w' => null], $row);
                }
            }
        }
    }

    if (!$sw) {
        echo json_encode(['success' => false, 'error' => 'Switch bulunamadı']);
        exit;
    }

    // DB'de PoE verisi varsa hemen döndür (hızlı yol)
    $dbNominal  = isset($sw['db_poe_nominal_w'])  ? intval($sw['db_poe_nominal_w'])  : null;
    $dbConsumed = isset($sw['db_poe_consumed_w']) ? intval($sw['db_poe_consumed_w']) : 0;
    if ($dbNominal !== null && $dbNominal > 0) {
        $usagePct = round($dbConsumed / $dbNominal * 100);
        echo json_encode([
            'success'   => true,
            'nominal_w' => $dbNominal,
            'used_w'    => $dbConsumed,
            'usage_pct' => $usagePct,
            'source'    => 'db',
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // ── 2. Canlı SNMP fallback ───────────────────────────────────────────────
    if (empty($sw['ip_address'])) {
        $creds = getSnmpCredsFromConfig($sw['ip'] ?? '');
        if ($creds) {
            $sw = array_merge($sw, $creds);
        } else {
            echo json_encode(['success' => false, 'error' => 'SNMP yapılandırması yok']);
            exit;
        }
    }

    if (!extension_loaded('snmp')) {
        // Extension is disabled (e.g. Windows OPcache/JIT + php_snmp.dll crash fix).
        // DB-first path above already checked poe_nominal_w/poe_consumed_w; if we
        // reach here those columns were NULL, meaning no PoE data is available yet.
        echo json_encode(['success' => false, 'error' => 'PoE verisi henüz hazır değil (Python worker bekleniyor)']);
        exit;
    }

    $ip = $sw['ip_address'];
    if ($sw['snmp_version'] === '3') {
        $authProto = (strtoupper($sw['snmp_v3_auth_protocol'] ?? 'SHA') === 'MD5') ? 'MD5' : 'SHA';
        $privProto = (strtoupper($sw['snmp_v3_priv_protocol'] ?? 'AES') === 'DES') ? 'DES' : 'AES';
        $engineId  = !empty($sw['snmp_engine_id']) ? $sw['snmp_engine_id'] : '';
        $snmp = new SNMP(SNMP::VERSION_3, $ip, $sw['snmp_v3_username'] ?? 'snmpuser');
        $snmp->setSecurity('authPriv', $authProto,
            $sw['snmp_v3_auth_password'] ?? '',
            $privProto, $sw['snmp_v3_priv_password'] ?? '',
            /* contextName */ '', /* contextEngineID */ $engineId);
    } else {
        $snmp = new SNMP(SNMP::VERSION_2c, $ip, $sw['snmp_community'] ?? 'public');
    }
    $snmp->valueretrieval = SNMP_VALUE_PLAIN;
    $snmp->quick_print    = true;
    $snmp->timeout        = 2000000;
    $snmp->retries        = 1;

    // Walk pethMainPseNominalPower table (1.3.6.1.2.1.105.1.3.1.2) — handles
    // any module group index (CBS350 stack may use index other than .1).
    $nominal     = 0;
    $consumption = 0;
    $operStatus  = 0;

    try {
        $nomWalk = @$snmp->walk('1.3.6.1.2.1.105.1.3.1.2');  // pethMainPseNominalPower
        if ($nomWalk && is_array($nomWalk)) {
            foreach ($nomWalk as $oid => $val) {
                $n = intval(poeParseVal($val));
                if ($n > 0) {
                    $nominal = $n;
                    // Extract the module group index suffix (e.g. ".1") from the OID
                    $suffix = substr((string)$oid, strrpos((string)$oid, '.'));
                    $consumption = intval(poeParseVal(
                        @$snmp->get('1.3.6.1.2.1.105.1.3.1.4' . $suffix)  // pethMainPseConsumptionPower
                    ));
                    $operStatus = intval(poeParseVal(
                        @$snmp->get('1.3.6.1.2.1.105.1.3.1.3' . $suffix)  // pethMainPseOperStatus
                    ));
                    break;
                }
            }
        }
    } catch (Throwable $ignored) {}

    if ($nominal <= 0) {
        echo json_encode(['success' => false, 'error' => 'PoE verisi alınamadı']);
        exit;
    }

    $usagePct = round($consumption / $nominal * 100);

    echo json_encode([
        'success'     => true,
        'nominal_w'   => $nominal,
        'used_w'      => $consumption,
        'usage_pct'   => $usagePct,
        'oper_status' => match($operStatus) { 1 => 'on', 2 => 'off', 3 => 'faulty', default => 'unknown' },
        'source'      => 'snmp',
    ], JSON_UNESCAPED_UNICODE);

} catch (Throwable $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
