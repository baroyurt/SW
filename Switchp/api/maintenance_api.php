<?php
/**
 * Maintenance Window API
 * CRUD for scheduled maintenance windows.
 * Admin-only write access; read access for all authenticated users.
 */
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

session_start();
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

$currentUser = $auth->getUser();
$isAdmin     = ($currentUser['role'] === 'admin');

session_write_close();
header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

switch ($action) {
    case 'list':
        listWindows($conn);
        break;
    case 'active':
        getActiveWindow($conn);
        break;
    case 'create':
        if ($method !== 'POST') { echo json_encode(['error' => 'POST required']); break; }
        if (!$isAdmin) { http_response_code(403); echo json_encode(['error' => 'Admin required']); break; }
        createWindow($conn, $currentUser);
        break;
    case 'update':
        if ($method !== 'POST') { echo json_encode(['error' => 'POST required']); break; }
        if (!$isAdmin) { http_response_code(403); echo json_encode(['error' => 'Admin required']); break; }
        updateWindow($conn, $currentUser);
        break;
    case 'delete':
        if ($method !== 'POST') { echo json_encode(['error' => 'POST required']); break; }
        if (!$isAdmin) { http_response_code(403); echo json_encode(['error' => 'Admin required']); break; }
        deleteWindow($conn);
        break;
    default:
        echo json_encode(['error' => 'Invalid action']);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ensureTable($conn) {
    $conn->query("CREATE TABLE IF NOT EXISTS maintenance_windows (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        title        VARCHAR(255)  NOT NULL,
        description  TEXT          DEFAULT NULL,
        start_time   DATETIME      NOT NULL,
        end_time     DATETIME      NOT NULL,
        created_by   VARCHAR(100)  DEFAULT NULL,
        is_active    TINYINT(1)    NOT NULL DEFAULT 1,
        notify_users TINYINT(1)    NOT NULL DEFAULT 0,
        created_at   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
        updated_at   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_mw_times (start_time, end_time),
        INDEX idx_mw_active (is_active)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function listWindows($conn) {
    ensureTable($conn);
    $res  = $conn->query("SELECT * FROM maintenance_windows ORDER BY start_time DESC LIMIT 100");
    $rows = [];
    if ($res) { while ($r = $res->fetch_assoc()) { $rows[] = $r; } }
    echo json_encode(['success' => true, 'windows' => $rows]);
}

function getActiveWindow($conn) {
    ensureTable($conn);
    $now = date('Y-m-d H:i:s');
    $stmt = $conn->prepare(
        "SELECT * FROM maintenance_windows
         WHERE is_active = 1 AND start_time <= ? AND end_time >= ?
         ORDER BY start_time DESC LIMIT 1"
    );
    if (!$stmt) {
        echo json_encode(['active' => false]);
        return;
    }
    $stmt->bind_param('ss', $now, $now);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    echo json_encode(['active' => (bool)$row, 'window' => $row]);
}

function createWindow($conn, $user) {
    ensureTable($conn);
    $body = json_decode(file_get_contents('php://input'), true);

    $title   = trim($body['title']       ?? '');
    $desc    = trim($body['description'] ?? '');
    $start   = trim($body['start_time']  ?? '');
    $end     = trim($body['end_time']    ?? '');
    $notify  = isset($body['notify_users']) ? (int)(bool)$body['notify_users'] : 0;

    if (!$title || !$start || !$end) {
        echo json_encode(['error' => 'title, start_time and end_time are required']);
        return;
    }
    if (!validateDateTime($start) || !validateDateTime($end)) {
        echo json_encode(['error' => 'Invalid date format (YYYY-MM-DD HH:MM:SS)']);
        return;
    }
    if (strtotime($end) <= strtotime($start)) {
        echo json_encode(['error' => 'end_time must be after start_time']);
        return;
    }

    $createdBy = $user['username'] ?? $user['full_name'] ?? 'admin';
    $stmt = $conn->prepare(
        "INSERT INTO maintenance_windows (title, description, start_time, end_time, created_by, notify_users)
         VALUES (?, ?, ?, ?, ?, ?)"
    );
    $stmt->bind_param('sssssi', $title, $desc, $start, $end, $createdBy, $notify);
    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'id' => $conn->insert_id]);
    } else {
        echo json_encode(['error' => 'DB error: ' . $stmt->error]);
    }
}

function updateWindow($conn, $user) {
    ensureTable($conn);
    $body = json_decode(file_get_contents('php://input'), true);

    $id      = (int)($body['id']          ?? 0);
    $title   = trim($body['title']        ?? '');
    $desc    = trim($body['description']  ?? '');
    $start   = trim($body['start_time']   ?? '');
    $end     = trim($body['end_time']     ?? '');
    $active  = isset($body['is_active'])  ? (int)(bool)$body['is_active'] : 1;
    $notify  = isset($body['notify_users'])? (int)(bool)$body['notify_users'] : 0;

    if ($id <= 0 || !$title || !$start || !$end) {
        echo json_encode(['error' => 'id, title, start_time and end_time are required']);
        return;
    }
    if (!validateDateTime($start) || !validateDateTime($end)) {
        echo json_encode(['error' => 'Invalid date format']);
        return;
    }
    if (strtotime($end) <= strtotime($start)) {
        echo json_encode(['error' => 'end_time must be after start_time']);
        return;
    }

    $stmt = $conn->prepare(
        "UPDATE maintenance_windows
         SET title=?, description=?, start_time=?, end_time=?, is_active=?, notify_users=?
         WHERE id=?"
    );
    $stmt->bind_param('ssssiii', $title, $desc, $start, $end, $active, $notify, $id);
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'DB error: ' . $stmt->error]);
    }
}

function deleteWindow($conn) {
    ensureTable($conn);
    $body = json_decode(file_get_contents('php://input'), true);
    $id   = (int)($body['id'] ?? 0);
    if ($id <= 0) {
        echo json_encode(['error' => 'id required']);
        return;
    }
    $stmt = $conn->prepare("DELETE FROM maintenance_windows WHERE id=?");
    $stmt->bind_param('i', $id);
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'DB error: ' . $stmt->error]);
    }
}

function validateDateTime($dt) {
    if (!preg_match('/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?$/', $dt)) {
        return false;
    }
    // preg_match sadece format kontrol eder; tarih geçerliliğini strtotime ile doğrula
    $time = strtotime($dt);
    return $time !== false && $time > 0;
}
