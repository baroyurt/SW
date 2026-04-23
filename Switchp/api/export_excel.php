<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';
require_once __DIR__ . '/../core/email_template.php';

$auth = new Auth($conn);
$auth->requireLogin();

// ── Password-verify endpoint (POST JSON) ──────────────────────────────────
// Called by the frontend modal before the actual download redirect.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    session_write_close();
    $body = json_decode(file_get_contents('php://input'), true);
    $password = isset($body['password']) ? $body['password'] : '';
    if ($password === '') {
        echo json_encode(['success' => false, 'error' => 'Şifre boş olamaz.']);
        exit;
    }

    // Verify against the logged-in user's stored hash
    $userId = $_SESSION['user_id'] ?? null;
    if (!$userId) {
        echo json_encode(['success' => false, 'error' => 'Oturum bulunamadı.']);
        exit;
    }
    $stmt = $conn->prepare("SELECT password FROM users WHERE id = ? AND is_active = 1");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$row || !password_verify($password, $row['password'])) {
        echo json_encode(['success' => false, 'error' => 'Şifre yanlış.']);
        exit;
    }

    echo json_encode(['success' => true]);
    exit;
}

// Release PHP session lock so the download doesn't block other concurrent
// PHP requests that are waiting for the session (e.g. iframes in admin.php).
session_write_close();

$type = isset($_GET['type']) ? trim($_GET['type']) : 'switches';
$allowed = ['switches', 'racks', 'panels', 'all', 'flapping', 'errors', 'vlan_alias'];
if (!in_array($type, $allowed)) {
    http_response_code(400);
    exit('Geçersiz tür.');
}

// Output a CSV file
function outputCsv($filename, array $rows) {
    // Strip any characters that could break the Content-Disposition header value
    $filename = preg_replace('/[^A-Za-z0-9_\-\.]/', '_', $filename);
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');

    $out = fopen('php://output', 'w');
    // UTF-8 BOM so Excel recognises encoding
    fwrite($out, "\xEF\xBB\xBF");
    foreach ($rows as $row) {
        fputcsv($out, $row, ';');
    }
    fclose($out);
}

// ─── Switches ─────────────────────────────────────────────────────────────
function getSwitchRows($conn) {
    $rows = [['ID', 'Ad', 'Marka', 'Model', 'Port Sayısı', 'IP Adresi', 'Durum', 'Rack', 'Rack Konum']];
    $res = $conn->query("
        SELECT s.id, s.name, s.brand, s.model, s.ports, s.ip, s.status,
               r.name AS rack_name, r.location AS rack_location
        FROM switches s
        LEFT JOIN racks r ON s.rack_id = r.id
        ORDER BY s.name
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = [
                $row['id'], $row['name'], $row['brand'], $row['model'],
                $row['ports'], $row['ip'], $row['status'],
                $row['rack_name'] ?? '', $row['rack_location'] ?? ''
            ];
        }
    }
    return $rows;
}

// ─── Racks ────────────────────────────────────────────────────────────────
function getRackRows($conn) {
    $rows = [['ID', 'Ad', 'Konum', 'Slot Sayısı', 'Açıklama']];
    $res = $conn->query("SELECT id, name, location, slots, description FROM racks ORDER BY name");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = [$row['id'], $row['name'], $row['location'], $row['slots'], $row['description'] ?? ''];
        }
    }
    return $rows;
}

// ─── Panels (Patch + Fiber) ────────────────────────────────────────────────
function getPanelRows($conn) {
    $rows = [['Tür', 'ID', 'Harf', 'Rack', 'Rack Konum', 'Port Sayısı', 'Açıklama']];
    $data = [];

    // Patch panels
    $res = $conn->query("
        SELECT 'Patch Panel' AS panel_type, pp.id, pp.panel_letter,
               r.name AS rack_name, r.location AS rack_location,
               pp.total_ports AS port_count, pp.description
        FROM patch_panels pp
        LEFT JOIN racks r ON pp.rack_id = r.id
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $data[] = $row;
        }
    }

    // Fiber panels
    $res2 = $conn->query("
        SELECT 'Fiber Panel' AS panel_type, fp.id, fp.panel_letter,
               r.name AS rack_name, r.location AS rack_location,
               fp.total_fibers AS port_count, fp.description
        FROM fiber_panels fp
        LEFT JOIN racks r ON fp.rack_id = r.id
    ");
    if ($res2) {
        while ($row = $res2->fetch_assoc()) {
            $data[] = $row;
        }
    }

    // Sort by rack name then panel letter in PHP to avoid UNION ORDER BY issues
    usort($data, function($a, $b) {
        $rackCmp = strcmp($a['rack_name'] ?? '', $b['rack_name'] ?? '');
        if ($rackCmp !== 0) return $rackCmp;
        return strcmp($a['panel_letter'] ?? '', $b['panel_letter'] ?? '');
    });

    foreach ($data as $row) {
        $rows[] = [
            $row['panel_type'], $row['id'], $row['panel_letter'],
            $row['rack_name'] ?? '', $row['rack_location'] ?? '',
            $row['port_count'] ?? '', $row['description'] ?? ''
        ];
    }
    return $rows;
}

// ─── Ports ────────────────────────────────────────────────────────────────
function getPortRows($conn) {
    $rows = [['Switch', 'Port No', 'Tür', 'Cihaz', 'IP', 'MAC', 'Aktif']];
    $res = $conn->query("
        SELECT s.name AS switch_name, p.port_no, p.type, p.device, p.ip, p.mac,
               CASE WHEN (p.ip IS NOT NULL AND p.ip != '') OR (p.mac IS NOT NULL AND p.mac != '')
                    OR (p.device IS NOT NULL AND p.device != '' AND p.device != 'BOŞ')
                    THEN 'Evet' ELSE 'Hayır' END AS is_active
        FROM ports p
        LEFT JOIN switches s ON p.switch_id = s.id
        ORDER BY s.name, p.port_no
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = [
                $row['switch_name'] ?? '', $row['port_no'], $row['type'],
                $row['device'], $row['ip'], $row['mac'], $row['is_active']
            ];
        }
    }
    return $rows;
}

// ─── Flapping (Up/Down Döngüsü) ───────────────────────────────────────────
function getFlappingRows($conn) {
    $rows = [['Switch', 'IP', 'Port', 'Alias', 'VLAN', 'Değişim Sayısı', 'İlk Değişim', 'Son Değişim']];
    $res  = $conn->query("
        SELECT
            sd.name        AS switch_name,
            sd.ip_address,
            pch.port_number,
            COALESCE(psd.port_alias, '') AS alias,
            psd.vlan_id,
            COUNT(*) AS change_count,
            MIN(pch.change_timestamp) AS first_change,
            MAX(pch.change_timestamp) AS last_change
        FROM port_change_history pch
        JOIN snmp_devices sd ON sd.id = pch.device_id
        LEFT JOIN port_status_data psd ON psd.device_id = pch.device_id AND psd.port_number = pch.port_number
        WHERE pch.change_timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        GROUP BY sd.name, sd.ip_address, pch.port_number, psd.port_alias, psd.vlan_id
        HAVING COUNT(*) >= 3
        ORDER BY change_count DESC, sd.name, pch.port_number
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = [
                $row['switch_name'] ?? '',
                $row['ip_address']  ?? '',
                (int)$row['port_number'],
                $row['alias']       ?? '',
                $row['vlan_id']     ?? '',
                (int)$row['change_count'],
                !empty($row['first_change']) ? date('d.m.Y H:i:s', strtotime($row['first_change'])) : '',
                !empty($row['last_change'])  ? date('d.m.Y H:i:s', strtotime($row['last_change']))  : '',
            ];
        }
    }
    return $rows;
}

// ─── Errors / Drop ────────────────────────────────────────────────────────
function getErrorRows($conn) {
    $rows = [['Switch', 'IP', 'Port', 'Cihaz/Alias', 'VLAN', 'Durum', 'Gelen Hata', 'Giden Hata', 'Output Drop', 'Toplam', 'Son Poll']];
    $res  = $conn->query("
        SELECT
            sd.name  AS switch_name,
            sd.ip_address,
            psd.port_number,
            COALESCE(psd.port_alias,'') AS port_alias,
            psd.vlan_id,
            psd.oper_status,
            COALESCE(psd.in_errors,   0) AS in_errors,
            COALESCE(psd.out_errors,  0) AS out_errors,
            COALESCE(psd.out_discards,0) AS out_discards,
            COALESCE(psd.in_errors,0)+COALESCE(psd.out_errors,0)+COALESCE(psd.out_discards,0) AS total_issues,
            psd.poll_timestamp
        FROM port_status_data psd
        JOIN snmp_devices sd ON sd.id = psd.device_id
        WHERE (COALESCE(psd.in_errors,0) > 0 OR COALESCE(psd.out_errors,0) > 0 OR COALESCE(psd.out_discards,0) > 0)
        ORDER BY total_issues DESC, sd.name, psd.port_number
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = [
                $row['switch_name'] ?? '',
                $row['ip_address']  ?? '',
                (int)$row['port_number'],
                $row['port_alias']  ?? '',
                $row['vlan_id']     ?? '',
                strtoupper($row['oper_status'] ?? ''),
                (int)$row['in_errors'],
                (int)$row['out_errors'],
                (int)$row['out_discards'],
                (int)$row['total_issues'],
                !empty($row['poll_timestamp']) ? date('d.m.Y H:i:s', strtotime($row['poll_timestamp'])) : '',
            ];
        }
    }
    return $rows;
}

// ─── VLAN / Alias Uyumsuzluk ──────────────────────────────────────────────
function getVlanAliasRows($conn) {
    $rows = [['Switch', 'IP', 'Port', 'VLAN ID', 'VLAN Tipi (Beklenen)', 'Alias Tipi (Algılanan)', 'Mevcut Alias', 'Durum', 'Son Güncelleme']];
    $res  = $conn->query("
        SELECT
            sd.name       AS switch_name,
            sd.ip_address AS switch_ip,
            psd.port_number,
            psd.vlan_id,
            COALESCE(psd.port_alias,'') AS alias,
            psd.oper_status,
            psd.poll_timestamp
        FROM port_status_data psd
        JOIN snmp_devices sd ON sd.id = psd.device_id
        WHERE psd.vlan_id IS NOT NULL AND psd.port_alias IS NOT NULL AND psd.port_alias != ''
        ORDER BY sd.name, psd.port_number
    ");
    if (!$res) return $rows;

    $vlanTypeMap = [
        30=>'GUEST',40=>'VIP',50=>'DEVICE',70=>'AP',80=>'KAMERA',
        110=>'SES',120=>'OTOMASYON',130=>'IPTV',140=>'SANTRAL',
        150=>'JACKPOT',254=>'SERVER',1500=>'DRGT',
    ];
    $typeList = array_values($vlanTypeMap);

    while ($row = $res->fetch_assoc()) {
        $vlanId = (int)$row['vlan_id'];
        if (!isset($vlanTypeMap[$vlanId])) continue;
        $expectedType = $vlanTypeMap[$vlanId];
        $detectedType = detectAliasTypeExport(trim($row['alias']), $typeList);
        if ($detectedType === null || strtoupper($detectedType) === strtoupper($expectedType)) continue;
        $rows[] = [
            $row['switch_name'] ?? '',
            $row['switch_ip']   ?? '',
            (int)$row['port_number'],
            $vlanId,
            $expectedType,
            $detectedType,
            $row['alias'],
            strtoupper($row['oper_status'] ?? ''),
            !empty($row['poll_timestamp']) ? date('d.m.Y H:i:s', strtotime($row['poll_timestamp'])) : '',
        ];
    }
    return $rows;
}

function detectAliasTypeExport(string $alias, array $typeList): ?string {
    $alias     = strtoupper(trim($alias));
    $aliasNorm = preg_replace('/[\s\-_]+/', '', $alias);
    foreach ($typeList as $type) {
        $t = strtoupper($type);
        $tNorm = preg_replace('/[\s\-_]+/', '', $t);
        if ($alias === $t) return $type;
        if (preg_match('/^' . preg_quote($t, '/') . '[\s\-_:\/]/', $alias)) return $type;
        if (preg_match('/(?:^|[\s\-_])' . preg_quote($t, '/') . '(?:$|[\s\-_])/', $alias)) return $type;
        if ($aliasNorm === $tNorm) return $type;
        if ($tNorm !== '' && str_contains($aliasNorm, $tNorm)) return $type;
    }
    return null;
}

// ─── Dispatch ─────────────────────────────────────────────────────────────
$date = date('Ymd_His');  // used in all filenames; date() output contains only safe chars

// Send email notification about this export
$exportLabels = [
    'switches'   => 'Switch Verisi',
    'racks'      => 'Rack Verisi',
    'panels'     => 'Panel Verisi',
    'all'        => 'Tüm Veri',
    'flapping'   => 'Up/Down Döngüsü Raporu',
    'errors'     => 'Hata / Drop Raporu',
    'vlan_alias' => 'VLAN/Alias Uyumsuzluk Raporu',
];
$exportLabel = $exportLabels[$type] ?? $type;
$username    = $_SESSION['username']  ?? 'Bilinmiyor';
$fullName    = $_SESSION['full_name'] ?? $username;
$clientIp    = $_SERVER['HTTP_X_FORWARDED_FOR']
               ?? $_SERVER['HTTP_CLIENT_IP']
               ?? $_SERVER['REMOTE_ADDR']
               ?? 'Bilinmiyor';
$dateHuman   = date('d.m.Y H:i:s');

// Build and send notification email (non-blocking; ignore send errors)
(function() use ($exportLabel, $username, $fullName, $clientIp, $dateHuman) {
    $configPath = __DIR__ . '/../snmp_worker/config/config.yml';
    if (!file_exists($configPath)) return;
    $content = @file_get_contents($configPath);
    if (!$content) return;

    if (!preg_match(
        '/email:\s+enabled:\s*(true|false)\s+smtp_host:\s*"([^"]*)"\s+smtp_port:\s*([^\s]+)\s+smtp_user:\s*"([^"]*)"\s+smtp_password:\s*"([^"]*)"\s+from_address:\s*"([^"]*)"/s',
        $content, $m
    ) || $m[1] !== 'true') return;

    $toAddresses = [];
    if (preg_match('/to_addresses:\s*((?:\s*-\s*"[^"]*"\s*)+)/', $content, $tm)) {
        preg_match_all('/-\s*"([^"]*)"/', $tm[1], $addrMatches);
        $toAddresses = array_filter($addrMatches[1]);
    }
    if (empty($toAddresses)) return;

    $subject  = "CHAMADA Excel Export Bildirimi";
    $exContent = "<p style='margin:0 0 14px;font-size:15px;font-weight:700;color:#3498db;'>📊 Excel Export Bildirimi</p>"
        . "<p style='margin:4px 0;'><strong style='color:#8899bb;'>Export Türü:</strong> " . htmlspecialchars($exportLabel) . "</p>"
        . "<p style='margin:4px 0;'><strong style='color:#8899bb;'>Tarih / Saat:</strong> " . htmlspecialchars($dateHuman) . "</p>";
    $htmlBody = chamada_email_template('Excel Export Bildirimi', $exContent, $username, $fullName, $clientIp);

    $port    = (int)$m[3];
    $host    = $m[2];
    $user    = $m[4];
    $pass    = $m[5];
    $from    = $m[6] ?: $user;
    $tos     = array_values($toAddresses);

    $boundary = md5(uniqid());
    $plainBody = strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $htmlBody));
    $message = "MIME-Version: 1.0\r\n"
        . "Content-Type: multipart/alternative; boundary=\"{$boundary}\"\r\n\r\n"
        . "--{$boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
        . $plainBody . "\r\n"
        . "--{$boundary}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n"
        . $htmlBody . "\r\n"
        . "--{$boundary}--\r\n";

    try {
        $useImplicitTLS = ($port === 465);
        $proto  = $useImplicitTLS ? 'ssl' : 'tcp';
        $ctx    = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
        $sock   = @stream_socket_client("{$proto}://{$host}:{$port}", $errno, $errstr, 15,
                                        STREAM_CLIENT_CONNECT, $ctx);
        if (!$sock) return;
        stream_set_timeout($sock, 15);
        $read = function() use ($sock) {
            $buf = '';
            while (($line = fgets($sock, 1024)) !== false) {
                $buf .= $line;
                if (isset($line[3]) && $line[3] === ' ') break;
            }
            return trim($buf);
        };
        $greeting = $read();
        if (substr($greeting, 0, 3) !== '220') { fclose($sock); return; }
        fwrite($sock, "EHLO " . gethostname() . "\r\n"); $read();
        if (!$useImplicitTLS) {
            fwrite($sock, "STARTTLS\r\n");
            $r = $read();
            if (substr($r, 0, 3) !== '220') { fclose($sock); return; }
            if (!stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) { fclose($sock); return; }
            fwrite($sock, "EHLO " . gethostname() . "\r\n"); $read();
        }
        fwrite($sock, "AUTH LOGIN\r\n");
        $r = $read();
        if (substr($r, 0, 3) !== '334') { fclose($sock); return; }
        fwrite($sock, base64_encode($user) . "\r\n"); $read();
        fwrite($sock, base64_encode($pass) . "\r\n");
        $r = $read();
        if (substr($r, 0, 3) !== '235') { fclose($sock); return; }
        fwrite($sock, "MAIL FROM:<{$from}>\r\n"); $read();
        foreach ($tos as $to) { fwrite($sock, "RCPT TO:<{$to}>\r\n"); $read(); }
        fwrite($sock, "DATA\r\n"); $read();
        $headers = "From: {$from}\r\nTo: " . implode(', ', $tos) . "\r\nSubject: =?UTF-8?B?" . base64_encode($subject) . "?=\r\nDate: " . date('r') . "\r\n";
        fwrite($sock, $headers . $message . "\r\n.\r\n");
        $read();
        fwrite($sock, "QUIT\r\n");
        fclose($sock);
    } catch (Throwable $e) { /* silently ignore */ }
})();

// Clear any output that was buffered by db.php's ob_start() before sending file headers
while (ob_get_level() > 0) { ob_end_clean(); }

if ($type === 'switches') {
    outputCsv('switches_' . $date . '.csv', getSwitchRows($conn));
} elseif ($type === 'racks') {
    outputCsv('racks_' . $date . '.csv', getRackRows($conn));
} elseif ($type === 'panels') {
    outputCsv('panels_' . $date . '.csv', getPanelRows($conn));
} elseif ($type === 'flapping') {
    outputCsv('updown_dongu_' . $date . '.csv', getFlappingRows($conn));
} elseif ($type === 'errors') {
    outputCsv('hata_drop_' . $date . '.csv', getErrorRows($conn));
} elseif ($type === 'vlan_alias') {
    outputCsv('vlan_alias_uyumsuzluk_' . $date . '.csv', getVlanAliasRows($conn));
} elseif ($type === 'all') {
    // Produce one multi-section CSV
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="export_all_' . $date . '.csv"');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');

    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");

    fputcsv($out, ['=== SWITCHLER ==='], ';');
    foreach (getSwitchRows($conn) as $row) fputcsv($out, $row, ';');

    fputcsv($out, [], ';');
    fputcsv($out, ['=== RACKLER ==='], ';');
    foreach (getRackRows($conn) as $row) fputcsv($out, $row, ';');

    fputcsv($out, [], ';');
    fputcsv($out, ['=== PANELLER ==='], ';');
    foreach (getPanelRows($conn) as $row) fputcsv($out, $row, ';');

    fputcsv($out, [], ';');
    fputcsv($out, ['=== PORTLAR ==='], ';');
    foreach (getPortRows($conn) as $row) fputcsv($out, $row, ';');

    fclose($out);
}
?>
