<?php
/**
 * verify_password_api.php
 * Verifies the current logged-in user's password.
 * POST body: { "password": "..." }
 * Returns:   { "success": true/false, "message": "..." }
 */
header('Content-Type: application/json');

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

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

$data     = json_decode(file_get_contents('php://input'), true) ?? [];
$password = $data['password'] ?? '';

if ($password === '') {
    echo json_encode(['success' => false, 'message' => 'Şifre boş olamaz.']);
    exit;
}

$currentUser = $auth->getUser();
$userId      = $currentUser['id'] ?? null;

if (!$userId) {
    echo json_encode(['success' => false, 'message' => 'Kullanıcı bilgisi alınamadı.']);
    exit;
}

$stmt = $conn->prepare("SELECT password FROM users WHERE id = ? AND is_active = 1");
$stmt->bind_param("i", $userId);
$stmt->execute();
$result = $stmt->get_result();
$row    = $result ? $result->fetch_assoc() : null;
$stmt->close();

if (!$row) {
    echo json_encode(['success' => false, 'message' => 'Kullanıcı bulunamadı.']);
    exit;
}

if (!password_verify($password, $row['password'])) {
    echo json_encode(['success' => false, 'message' => 'Şifre hatalı.']);
    exit;
}

echo json_encode(['success' => true, 'message' => 'Şifre doğrulandı.']);
