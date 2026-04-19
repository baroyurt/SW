<?php
// MAC History Cleanup API – deletes entries older than N days from mac_history.json
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';
require_once __DIR__ . '/../core/email_template.php';
require_once __DIR__ . '/../core/EmailService.php';

header('Content-Type: application/json');

$auth = new Auth($conn);
if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Yetkisiz erişim.']);
    exit;
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
    EmailService::send($subject, $htmlBody);
}

echo json_encode([
    'success'   => true,
    'deleted'   => $deleted,
    'remaining' => count($kept),
    'message'   => $deleted > 0
        ? "{$deleted} kayıt silindi, " . count($kept) . " kayıt kaldı."
        : "Silinen kayıt yok. Tüm kayıtlar {$days} günden yeni.",
]);
