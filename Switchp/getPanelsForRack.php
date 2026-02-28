<?php
// getPanelsForRack.php
require_once __DIR__ . '/core/ErrorHandler.php';
require_once __DIR__ . '/core/Database.php';

ErrorHandler::init();
header('Content-Type: application/json; charset=utf-8');

$rackId = isset($_GET['rack_id']) ? intval($_GET['rack_id']) : 0;
$type = isset($_GET['type']) ? $_GET['type'] : 'patch'; // patch or fiber

if ($rackId <= 0) {
    echo json_encode(['success' => false, 'message' => 'rack_id required']);
    exit;
}

$db = Database::getInstance();
$mysqli = $db->getConnection();

try {
    if ($type === 'patch') {
        $stmt = $mysqli->prepare("SELECT * FROM patch_panels WHERE rack_id = ? ORDER BY panel_letter");
    } else {
        $stmt = $mysqli->prepare("SELECT * FROM fiber_panels WHERE rack_id = ? ORDER BY panel_letter");
    }
    $stmt->bind_param("i", $rackId);
    $stmt->execute();
    $res = $stmt->get_result();
    $panels = [];
    while ($row = $res->fetch_assoc()) $panels[] = $row;
    $stmt->close();

    echo json_encode(['success' => true, 'panels' => $panels]);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}