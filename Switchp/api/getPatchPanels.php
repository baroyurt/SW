<?php
header('Content-Type: application/json; charset=utf-8');

include __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';
$auth = new Auth($conn);
if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

$rackId = isset($_GET['rack_id']) ? intval($_GET['rack_id']) : 0;
if ($rackId <= 0) {
    echo json_encode(['success' => false, 'message' => 'Geçersiz rack_id', 'panels' => []]);
    exit;
}

$stmt = $conn->prepare(
    "SELECT id, panel_letter, total_ports, position_in_rack
     FROM patch_panels WHERE rack_id = ? ORDER BY panel_letter"
);
$stmt->bind_param("i", $rackId);
$stmt->execute();
$result = $stmt->get_result();
$panels = [];
while ($row = $result->fetch_assoc()) {
    $panels[] = $row;
}
$stmt->close();
echo json_encode(['success' => true, 'panels' => $panels]);
