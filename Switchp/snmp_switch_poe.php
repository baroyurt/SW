<?php
/**
 * snmp_switch_poe.php — Switch düzeyinde PoE güç bütçesi
 * Kullanım: GET ?switch_id=93
 * pethMainPseTable (1.3.6.1.2.1.105.1.3.1) okur:
 *   .2.1 = Nominal power (W), .3.1 = OperStatus, .4.1 = Consumption power (W)
 */
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

header('Content-Type: application/json; charset=utf-8');
header("Cache-Control: no-cache, no-store, must-revalidate");

try {
    $switchId = intval($_GET['switch_id'] ?? 0);
    if (!$switchId) {
        echo json_encode(['success' => false, 'error' => 'switch_id gerekli']);
        exit;
    }

    $stmt = $conn->prepare("
        SELECT s.name, s.ip, s.model, sd.ip_address, sd.snmp_version,
               sd.snmp_v3_username, sd.snmp_v3_auth_protocol,
               sd.snmp_v3_auth_password, sd.snmp_v3_priv_protocol,
               sd.snmp_v3_priv_password, sd.snmp_community,
               sd.snmp_engine_id
        FROM switches s
        LEFT JOIN snmp_devices sd ON (s.name = sd.name OR s.ip = sd.ip_address)
        WHERE s.id = ?
    ");
    $stmt->bind_param('i', $switchId);
    $stmt->execute();
    $sw = $stmt->get_result()->fetch_assoc();

    if (!$sw || empty($sw['ip_address'])) {
        echo json_encode(['success' => false, 'error' => 'SNMP yapılandırması yok']);
        exit;
    }

    if (!extension_loaded('snmp')) {
        echo json_encode(['success' => false, 'error' => 'PHP SNMP eklentisi yüklü değil']);
        exit;
    }

    $ip = $sw['ip_address'];
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
    $snmp->quick_print    = true;
    $snmp->timeout        = 2000000;
    $snmp->retries        = 1;

    // pethMainPseTable module 1 (index .1)
    $nominal     = intval(@$snmp->get('1.3.6.1.2.1.105.1.3.1.2.1'));  // Watts
    $operStatus  = intval(@$snmp->get('1.3.6.1.2.1.105.1.3.1.3.1'));  // 1=on,2=off,3=faulty
    $consumption = intval(@$snmp->get('1.3.6.1.2.1.105.1.3.1.4.1')); // Watts

    if ($nominal <= 0) {
        echo json_encode(['success' => false, 'error' => 'PoE verisi alınamadı']);
        exit;
    }

    $usagePct = $nominal > 0 ? round($consumption / $nominal * 100) : 0;

    echo json_encode([
        'success'     => true,
        'nominal_w'   => $nominal,
        'used_w'      => $consumption,
        'usage_pct'   => $usagePct,
        'oper_status' => match($operStatus) { 1 => 'on', 2 => 'off', 3 => 'faulty', default => 'unknown' },
    ], JSON_UNESCAPED_UNICODE);

} catch (Throwable $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
