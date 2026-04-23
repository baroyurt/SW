<?php
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

// Ensure table exists (global, not per-user)
$conn->query("CREATE TABLE IF NOT EXISTS report_hidden_ports (
    row_key VARCHAR(200) NOT NULL,
    PRIMARY KEY (row_key)
)");

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // Return all hidden row keys
    $stmt = $conn->query("SELECT row_key FROM report_hidden_ports");
    $keys = $stmt ? array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'row_key') : [];
    echo json_encode(['success' => true, 'hidden' => $keys]);

} elseif ($method === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $action  = $data['action']  ?? '';
    $row_key = trim($data['row_key'] ?? '');

    if ($row_key === '') {
        echo json_encode(['success' => false, 'error' => 'row_key required']);
        exit();
    }

    if ($action === 'hide') {
        // Simple INSERT — PK constraint silently prevents duplicates via the wrapper's catch
        $stmt = $conn->prepare("INSERT INTO report_hidden_ports (row_key) VALUES (?)");
        $stmt->execute([$row_key]);
        echo json_encode(['success' => true]);

    } elseif ($action === 'show') {
        $stmt = $conn->prepare("DELETE FROM report_hidden_ports WHERE row_key = ?");
        $stmt->execute([$row_key]);
        echo json_encode(['success' => true]);

    } else {
        echo json_encode(['success' => false, 'error' => 'Unknown action']);
    }

} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
}
