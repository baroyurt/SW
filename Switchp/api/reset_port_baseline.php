<?php
/**
 * reset_port_baseline.php — Port Sayaç Baseline Sıfırlama API
 * Mevcut SNMP sayaç değerlerini baseline olarak kaydeder.
 * Sonraki görüntülemelerde delta (fark) değerleri gösterilir.
 */
ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit();
}

// Tablo yoksa oluştur
$conn->query("CREATE TABLE IF NOT EXISTS port_counter_baselines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    switch_id INT NOT NULL,
    port_number INT NOT NULL,
    baseline_in_errors BIGINT NOT NULL DEFAULT 0,
    baseline_out_discards BIGINT NOT NULL DEFAULT 0,
    baseline_in_discards BIGINT NOT NULL DEFAULT 0,
    baseline_out_errors BIGINT NOT NULL DEFAULT 0,
    baseline_in_octets BIGINT NOT NULL DEFAULT 0,
    baseline_out_octets BIGINT NOT NULL DEFAULT 0,
    reset_at DATETIME,
    reset_by VARCHAR(100),
    note TEXT,
    UNIQUE KEY uq_sw_port (switch_id, port_number)
)");

$data        = json_decode(file_get_contents('php://input'), true);
$switch_id   = isset($data['switch_id'])   ? (int)$data['switch_id']   : 0;
$port_number = isset($data['port_number']) ? (int)$data['port_number'] : 0;
$note        = trim($data['note'] ?? '');

if ($switch_id <= 0 || $port_number <= 0) {
    echo json_encode(['success' => false, 'error' => 'Geçersiz switch_id veya port_number']);
    exit();
}

// Mevcut SNMP değerlerini port_status_data'dan oku
$stmt = $conn->prepare(
    "SELECT in_errors, out_errors, out_discards, in_discards, in_octets, out_octets
     FROM port_status_data
     WHERE device_id = ? AND port_number = ?"
);
$stmt->execute([$switch_id, $port_number]);
$res      = $stmt->get_result();
$portData = $res ? $res->fetch_assoc() : null;

if (!$portData) {
    echo json_encode(['success' => false, 'error' => 'Port verisi bulunamadı']);
    exit();
}

$currentUser  = $_SESSION['username'] ?? 'unknown';
$userId       = $_SESSION['user_id']  ?? null;
$resetAt      = date('Y-m-d H:i:s');

$in_errors    = (int)($portData['in_errors']    ?? 0);
$out_discards = (int)($portData['out_discards'] ?? 0);
$in_discards  = (int)($portData['in_discards']  ?? 0);
$out_errors   = (int)($portData['out_errors']   ?? 0);
$in_octets    = (int)($portData['in_octets']    ?? 0);
$out_octets   = (int)($portData['out_octets']   ?? 0);

// Baseline var mı kontrol et → INSERT veya UPDATE
$chk = $conn->prepare(
    "SELECT id FROM port_counter_baselines WHERE switch_id = ? AND port_number = ?"
);
$chk->execute([$switch_id, $port_number]);
$existing = $chk->get_result()?->fetch_assoc();

if ($existing) {
    $upd = $conn->prepare(
        "UPDATE port_counter_baselines
         SET baseline_in_errors=?, baseline_out_discards=?, baseline_in_discards=?,
             baseline_out_errors=?, baseline_in_octets=?, baseline_out_octets=?,
             reset_at=?, reset_by=?, note=?
         WHERE switch_id=? AND port_number=?"
    );
    $upd->execute([
        $in_errors, $out_discards, $in_discards, $out_errors,
        $in_octets, $out_octets,
        $resetAt, $currentUser, $note ?: null,
        $switch_id, $port_number,
    ]);
} else {
    $ins = $conn->prepare(
        "INSERT INTO port_counter_baselines
         (switch_id, port_number, baseline_in_errors, baseline_out_discards,
          baseline_in_discards, baseline_out_errors, baseline_in_octets, baseline_out_octets,
          reset_at, reset_by, note)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)"
    );
    $ins->execute([
        $switch_id, $port_number,
        $in_errors, $out_discards, $in_discards, $out_errors,
        $in_octets, $out_octets,
        $resetAt, $currentUser, $note ?: null,
    ]);
}

// Activity log'a yaz
$auth->logActivity(
    $userId,
    $currentUser,
    'baseline_reset',
    "Baseline sıfırlama: SW-{$switch_id} Port-{$port_number}" . ($note ? " ({$note})" : '')
);

$resetAtFormatted = date('d.m.Y H:i', strtotime($resetAt));
echo json_encode(['success' => true, 'reset_at' => $resetAtFormatted, 'reset_by' => $currentUser]);
