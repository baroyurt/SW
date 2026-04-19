<?php
include __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$_hubAuth = new Auth($conn);
if (!$_hubAuth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

header('Content-Type: application/json; charset=utf-8');

// Ensure table exists
$conn->query("IF OBJECT_ID('dbo.hub_sw_port_connections','U') IS NULL
BEGIN
CREATE TABLE hub_sw_port_connections (
    id             INT IDENTITY(1,1) PRIMARY KEY,
    rack_device_id INT          NOT NULL,
    port_number    SMALLINT     NOT NULL,
    conn_type      VARCHAR(30)  NOT NULL DEFAULT 'device',
    device_name    VARCHAR(255) DEFAULT NULL,
    switch_id      INT          DEFAULT NULL,
    switch_port    INT          DEFAULT NULL,
    notes          NVARCHAR(MAX) DEFAULT NULL,
    updated_at     DATETIME     DEFAULT GETDATE(),
    CONSTRAINT uk_rdport UNIQUE (rack_device_id, port_number)
)
CREATE INDEX idx_rd ON hub_sw_port_connections(rack_device_id)
END");

$data = json_decode(file_get_contents("php://input"), true);
if (!$data) {
    die(json_encode(["success" => false, "error" => "Geçersiz veri"]));
}

try {
    $rdId    = intval($data['rdId'] ?? 0);
    $portNum = intval($data['portNum'] ?? 0);

    if ($rdId <= 0 || $portNum <= 0) {
        throw new Exception("Geçersiz rack_device_id veya port_number");
    }

    // Delete action
    if (($data['action'] ?? '') === 'delete') {
        $stmt = $conn->prepare("DELETE FROM hub_sw_port_connections WHERE rack_device_id = ? AND port_number = ?");
        $stmt->bind_param("ii", $rdId, $portNum);
        $stmt->execute();
        $stmt->close();
        echo json_encode(["success" => true, "message" => "Bağlantı silindi"]);
        exit;
    }

    $connType   = $data['connType']    ?? 'device';
    $deviceName = trim($data['deviceName'] ?? '');
    $notes      = trim($data['notes']      ?? '');
    $swId       = isset($data['swId'])   ? intval($data['swId'])   : null;
    $swPort     = isset($data['swPort']) ? intval($data['swPort']) : null;

    if ($connType === 'switch' && (!$swId || !$swPort)) {
        throw new Exception("Switch ve port seçiniz");
    }
    if ($connType === 'device' && $deviceName === '') {
        throw new Exception("Cihaz adı boş olamaz");
    }

    $upd = $conn->prepare("
        UPDATE hub_sw_port_connections
        SET conn_type=?, device_name=?, switch_id=?, switch_port=?, notes=?, updated_at=GETDATE()
        WHERE rack_device_id=? AND port_number=?
    ");
    $upd->bind_param("ssiisii", $connType, $deviceName, $swId, $swPort, $notes, $rdId, $portNum);
    $upd->execute();
    if ($conn->affected_rows == 0) {
        $ins = $conn->prepare("
            INSERT INTO hub_sw_port_connections (rack_device_id, port_number, conn_type, device_name, switch_id, switch_port, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        $ins->bind_param("iississ", $rdId, $portNum, $connType, $deviceName, $swId, $swPort, $notes);
        $ins->execute();
        $ins->close();
    }
    $upd->close();

    echo json_encode(["success" => true, "message" => "Bağlantı kaydedildi"]);

} catch (Exception $e) {
    echo json_encode(["success" => false, "error" => $e->getMessage()]);
}

$conn->close();
?>
