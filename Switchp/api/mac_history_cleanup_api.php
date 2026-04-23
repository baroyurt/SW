<?php
// MAC History Cleanup API – deletes entries older than N days from mac_history.json
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';
require_once __DIR__ . '/../core/email_template.php';

header('Content-Type: application/json');

$auth = new Auth($conn);
if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Yetkisiz erişim.']);
    exit;
}

// ── Email helpers (same SMTP implementation as device_import_api.php) ────────

function mhc_getSmtpConfig() {
    $configPath = __DIR__ . '/../snmp_worker/config/config.yml';
    if (!file_exists($configPath)) return null;
    $content = @file_get_contents($configPath);
    if (!$content) return null;
    if (!preg_match(
        '/email:\s+enabled:\s*(true|false)\s+smtp_host:\s*"([^"]*)"\s+smtp_port:\s*([^\s]+)\s+smtp_user:\s*"([^"]*)"\s+smtp_password:\s*"([^"]*)"\s+from_address:\s*"([^"]*)"/s',
        $content, $m
    )) return null;
    if ($m[1] !== 'true') return null;
    $toAddresses = [];
    if (preg_match('/to_addresses:\s*((?:\s*-\s*"[^"]*"\s*)+)/', $content, $tm)) {
        preg_match_all('/-\s*"([^"]*)"/', $tm[1], $addrMatches);
        $toAddresses = array_filter($addrMatches[1]);
    }
    if (empty($toAddresses)) return null;
    return [
        'smtp_host'     => $m[2],
        'smtp_port'     => (int)$m[3],
        'smtp_user'     => $m[4],
        'smtp_password' => $m[5],
        'from_address'  => $m[6],
        'to_addresses'  => array_values($toAddresses),
    ];
}

function mhc_sendEmail(string $subject, string $htmlBody): bool {
    $cfg = mhc_getSmtpConfig();
    if (!$cfg) return false;
    $boundary = md5(uniqid());
    $plainBody = strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $htmlBody));
    $message = "MIME-Version: 1.0\r\n"
        . "Content-Type: multipart/alternative; boundary=\"{$boundary}\"\r\n\r\n"
        . "--{$boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
        . $plainBody . "\r\n"
        . "--{$boundary}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n"
        . $htmlBody . "\r\n"
        . "--{$boundary}--\r\n";
    $port = $cfg['smtp_port']; $host = $cfg['smtp_host'];
    $user = $cfg['smtp_user']; $pass = $cfg['smtp_password'];
    $from = $cfg['from_address'] ?: $user; $tos = $cfg['to_addresses'];
    try {
        $useImplicitTLS = ($port === 465);
        $proto = $useImplicitTLS ? 'ssl' : 'tcp';
        $ctx   = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
        $sock  = @stream_socket_client("{$proto}://{$host}:{$port}", $errno, $errstr, 15,
                                       STREAM_CLIENT_CONNECT, $ctx);
        if (!$sock) return false;
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
        if (substr($greeting, 0, 3) !== '220') { fclose($sock); return false; }
        fwrite($sock, "EHLO " . gethostname() . "\r\n"); $read();
        if (!$useImplicitTLS) {
            fwrite($sock, "STARTTLS\r\n");
            $r = $read();
            if (substr($r, 0, 3) !== '220') { fclose($sock); return false; }
            if (!stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) { fclose($sock); return false; }
            fwrite($sock, "EHLO " . gethostname() . "\r\n"); $read();
        }
        fwrite($sock, "AUTH LOGIN\r\n");
        $r = $read();
        if (substr($r, 0, 3) !== '334') { fclose($sock); return false; }
        fwrite($sock, base64_encode($user) . "\r\n"); $read();
        fwrite($sock, base64_encode($pass) . "\r\n");
        $r = $read();
        if (substr($r, 0, 3) !== '235') { fclose($sock); return false; }
        fwrite($sock, "MAIL FROM:<{$from}>\r\n"); $read();
        foreach ($tos as $to) { fwrite($sock, "RCPT TO:<{$to}>\r\n"); $read(); }
        fwrite($sock, "DATA\r\n"); $read();
        $headers = "From: {$from}\r\nTo: " . implode(', ', $tos) . "\r\nSubject: {$subject}\r\nDate: " . date('r') . "\r\n";
        fwrite($sock, $headers . $message . "\r\n.\r\n");
        $r = $read();
        fwrite($sock, "QUIT\r\n");
        fclose($sock);
        return substr($r, 0, 3) === '250';
    } catch (\Throwable $e) {
        error_log("mhc_sendEmail error: " . $e->getMessage());
        return false;
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Geçersiz istek metodu.']);
    exit;
}

$days = isset($_POST['days']) ? (int)$_POST['days'] : 0;
if ($days <= 0) {
    echo json_encode(['success' => false, 'message' => 'Geçerli bir gün sayısı giriniz (en az 1).']);
    exit;
}

// Identify who is performing the deletion
$currentUser = $auth->getUser();
$deletedBy   = $currentUser['username'] ?? 'bilinmiyor';
$deletedByFullName = $currentUser['full_name'] ?? '';
$clientIpMhc = $_SERVER['HTTP_X_FORWARDED_FOR']
    ?? $_SERVER['HTTP_X_REAL_IP']
    ?? $_SERVER['REMOTE_ADDR']
    ?? '';

$historyFile = __DIR__ . '/../logs/mac_history.json';

if (!file_exists($historyFile)) {
    echo json_encode(['success' => true, 'deleted' => 0, 'remaining' => 0, 'message' => 'Temizlenecek kayıt yok.']);
    exit;
}

$cutoff = time() - ($days * 86400);

$fp = fopen($historyFile, 'c+');
if (!$fp || !flock($fp, LOCK_EX)) {
    if ($fp) fclose($fp);
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Dosya kilitlenemedi.']);
    exit;
}

$raw = stream_get_contents($fp);
$all = json_decode($raw, true);
if (!is_array($all)) {
    flock($fp, LOCK_UN);
    fclose($fp);
    echo json_encode(['success' => true, 'deleted' => 0, 'remaining' => 0, 'message' => 'Geçmişte kayıt bulunamadı.']);
    exit;
}

$before = count($all);
$kept   = array_values(array_filter($all, function ($entry) use ($cutoff) {
    $ts = $entry['timestamp'] ?? '';
    if ($ts === '') return true; // keep entries with no timestamp
    $time = strtotime($ts);
    return $time !== false && $time >= $cutoff;
}));

// Collect the entries that will be removed (for the notification email)
$deletedEntries = array_values(array_filter($all, function ($entry) use ($cutoff) {
    $ts = $entry['timestamp'] ?? '';
    if ($ts === '') return false;
    $time = strtotime($ts);
    return $time === false || $time < $cutoff;
}));

$deleted = $before - count($kept);

// Write back
rewind($fp);
ftruncate($fp, 0);
fwrite($fp, json_encode($kept, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
flock($fp, LOCK_UN);
fclose($fp);

// ── Send email notification when records were actually deleted ────────────────
if ($deleted > 0) {
    $actionLabels = [
        'device_registered' => 'Cihaz Kaydedildi',
        'mac_moved'         => 'MAC Taşındı',
        'mac_changed'       => 'MAC Değişti',
    ];

    $rows = '';
    foreach ($deletedEntries as $e) {
        $ts         = htmlspecialchars($e['timestamp']  ?? '-');
        $sw         = htmlspecialchars($e['switch']     ?? '-');
        $swIp       = htmlspecialchars($e['switch_ip']  ?? '-');
        $oldPort    = htmlspecialchars($e['old_port']   ?? '-');
        $newPort    = htmlspecialchars($e['new_port']   ?? '-');
        $oldMac     = htmlspecialchars($e['old_mac']    ?? '-');
        $newMac     = htmlspecialchars($e['new_mac']    ?? '-');
        $action     = $actionLabels[$e['action'] ?? ''] ?? htmlspecialchars($e['action'] ?? '-');
        $approvedBy = htmlspecialchars($e['approved_by'] ?? '-');
        $rows .= "<tr>
            <td style='padding:4px 8px;border:1px solid #1e2d4d;color:#c8d5e8;'>{$ts}</td>
            <td style='padding:4px 8px;border:1px solid #1e2d4d;color:#c8d5e8;'>{$sw}</td>
            <td style='padding:4px 8px;border:1px solid #1e2d4d;color:#c8d5e8;'>***</td><!-- Switch IP intentionally masked in email notifications -->
            <td style='padding:4px 8px;border:1px solid #1e2d4d;color:#c8d5e8;'>{$oldPort}</td>
            <td style='padding:4px 8px;border:1px solid #1e2d4d;color:#c8d5e8;'>{$newPort}</td>
            <td style='padding:4px 8px;border:1px solid #1e2d4d;color:#c8d5e8;font-family:monospace;'>{$oldMac}</td>
            <td style='padding:4px 8px;border:1px solid #1e2d4d;color:#c8d5e8;font-family:monospace;'>{$newMac}</td>
            <td style='padding:4px 8px;border:1px solid #1e2d4d;color:#c8d5e8;'>{$action}</td>
            <td style='padding:4px 8px;border:1px solid #1e2d4d;color:#c8d5e8;'>{$approvedBy}</td>
        </tr>\n";
    }

    $subject  = "CHAMADA MAC Değişim Geçmişi";
    $content  = "<p style='margin:0 0 14px;font-size:15px;font-weight:700;color:#d4a017;'>🗑️ Eski Kayıtlar Silindi</p>"
              . "<p style='margin:4px 0;'><strong style='color:#8899bb;'>Silme kriteri:</strong> {$days} günden eski kayıtlar</p>"
              . "<p style='margin:4px 0;'><strong style='color:#8899bb;'>Silinen kayıt sayısı:</strong> <span style='color:#e74c3c;font-weight:700;'>{$deleted}</span></p>"
              . "<p style='margin:4px 0;'><strong style='color:#8899bb;'>Kalan kayıt sayısı:</strong> " . count($kept) . "</p>"
              . "<p style='margin:4px 0;'><strong style='color:#8899bb;'>Tarih / Saat:</strong> " . date('d.m.Y H:i:s') . "</p>"
              . "<hr style='border:0;border-top:1px solid #1e2d4d;margin:18px 0;'>"
              . "<p style='margin:0 0 10px;font-weight:700;color:#e74c3c;'>Silinen Kayıtlar</p>"
              . "<table style='border-collapse:collapse;width:100%;font-size:12px;'>"
              . "<thead><tr style='background:#0d1527;color:#8899bb;'>"
              . "<th style='padding:6px 8px;border:1px solid #1e2d4d;'>Tarih / Saat</th>"
              . "<th style='padding:6px 8px;border:1px solid #1e2d4d;'>Switch</th>"
              . "<th style='padding:6px 8px;border:1px solid #1e2d4d;'>Switch IP</th>"
              . "<th style='padding:6px 8px;border:1px solid #1e2d4d;'>Eski Port</th>"
              . "<th style='padding:6px 8px;border:1px solid #1e2d4d;'>Yeni Port</th>"
              . "<th style='padding:6px 8px;border:1px solid #1e2d4d;'>Eski MAC</th>"
              . "<th style='padding:6px 8px;border:1px solid #1e2d4d;'>Yeni MAC</th>"
              . "<th style='padding:6px 8px;border:1px solid #1e2d4d;'>İşlem</th>"
              . "<th style='padding:6px 8px;border:1px solid #1e2d4d;'>Onaylayan</th>"
              . "</tr></thead>"
              . "<tbody>{$rows}</tbody></table>";

    $htmlBody = chamada_email_template('MAC Değişim Geçmişi', $content, $deletedBy, $deletedByFullName, $clientIpMhc);
    $mhcSent = mhc_sendEmail($subject, $htmlBody);
    // Log to email_log
    try {
        $mhcCfg = mhc_getSmtpConfig();
        if ($mhcCfg) {
            $tableChk = $conn->query("SELECT COUNT(*) as cnt FROM information_schema.tables WHERE table_name='email_log'");
            if ($tableChk && ($chkRow = $tableChk->fetch_assoc()) && (int)$chkRow['cnt']) {
                $mhcRecips = implode(', ', $mhcCfg['to_addresses'] ?? []);
                $mhcStatus = $mhcSent ? 'sent' : 'failed';
                $mhcSubjLog = $subject;
                $mhcType = 'mac_history_cleanup';
                $mhcStmt = $conn->prepare(
                    "INSERT INTO email_log (sent_at, subject, recipients, alarm_type, mail_type, status) VALUES (NOW(), ?, ?, NULL, ?, ?)"
                );
                if ($mhcStmt) {
                    $mhcStmt->bind_param('ssss', $mhcSubjLog, $mhcRecips, $mhcType, $mhcStatus);
                    $mhcStmt->execute();
                    $mhcStmt->close();
                }
            }
        }
    } catch (\Throwable $e) { /* ignore */ }
}

echo json_encode([
    'success'   => true,
    'deleted'   => $deleted,
    'remaining' => count($kept),
    'message'   => $deleted > 0
        ? "{$deleted} kayıt silindi, " . count($kept) . " kayıt kaldı."
        : "Silinen kayıt yok. Tüm kayıtlar {$days} günden yeni.",
]);
