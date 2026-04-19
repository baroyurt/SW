<?php
/**
 * saveRackDevice.php
 * Rack'teki Server ve Hub-SW cihazlarını yönetir.
 * Bu cihazlar SNMP ile izlenmez; sadece Raf Diyagramı ve
 * Network Topolojisinde görünür, Switch listesinde çıkmaz.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

header('Content-Type: application/json; charset=utf-8');

$auth = new Auth($conn);
$auth->requireLogin();

try {
    // Tablo yoksa oluştur
    $conn->query("IF OBJECT_ID('dbo.rack_devices','U') IS NULL
BEGIN
CREATE TABLE rack_devices (
    id               INT IDENTITY(1,1) PRIMARY KEY,
    rack_id          INT          NOT NULL,
    device_type      VARCHAR(20)  NOT NULL,
    name             VARCHAR(120) NOT NULL,
    ports            SMALLINT     NOT NULL DEFAULT 0,
    fiber_ports      SMALLINT     NOT NULL DEFAULT 0,
    unit_size        TINYINT      NOT NULL DEFAULT 1,
    position_in_rack TINYINT      DEFAULT NULL,
    notes            NVARCHAR(MAX) DEFAULT NULL,
    created_at       DATETIME     DEFAULT GETDATE(),
    updated_at       DATETIME     DEFAULT GETDATE()
)
CREATE INDEX idx_rack ON rack_devices(rack_id)
END");
    // Add fiber_ports column if it was missing from an older schema
    $conn->query("IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='rack_devices' AND COLUMN_NAME='fiber_ports') BEGIN ALTER TABLE rack_devices ADD fiber_ports SMALLINT NOT NULL DEFAULT 0 END");

    $method = $_SERVER['REQUEST_METHOD'];

    // ── GET: liste al ─────────────────────────────────────────
    if ($method === 'GET') {
        $rackId = isset($_GET['rack_id']) ? intval($_GET['rack_id']) : 0;
        if ($rackId > 0) {
            $stmt = $conn->prepare("SELECT * FROM rack_devices WHERE rack_id = ? ORDER BY CASE WHEN position_in_rack IS NULL THEN 1 ELSE 0 END, position_in_rack ASC, id ASC");
            $stmt->bind_param("i", $rackId);
        } else {
            $stmt = $conn->prepare("SELECT * FROM rack_devices ORDER BY rack_id, CASE WHEN position_in_rack IS NULL THEN 1 ELSE 0 END, position_in_rack ASC, id ASC");
        }
        $stmt->execute();
        $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
        foreach ($rows as &$r) {
            $r['id']          = (int)$r['id'];
            $r['rack_id']     = (int)$r['rack_id'];
            $r['ports']       = (int)$r['ports'];
            $r['fiber_ports'] = (int)($r['fiber_ports'] ?? 0);
            $r['unit_size']   = (int)$r['unit_size'];
            $r['position_in_rack'] = $r['position_in_rack'] !== null ? (int)$r['position_in_rack'] : null;
        }
        echo json_encode(['success' => true, 'devices' => $rows]);
        exit;
    }

    // ── POST: kaydet / sil ──────────────────────────────────────
    if ($method === 'POST') {
        $data   = json_decode(file_get_contents('php://input'), true) ?? [];
        $action = $data['action'] ?? 'save';

        if ($action === 'delete') {
            $id = intval($data['id'] ?? 0);
            if ($id <= 0) throw new Exception("Geçersiz ID");
            $stmt = $conn->prepare("DELETE FROM rack_devices WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $stmt->close();
            echo json_encode(['success' => true, 'message' => 'Cihaz silindi']);
            exit;
        }

        // save (insert or update)
        $id         = intval($data['id'] ?? 0);
        $rackId     = intval($data['rack_id'] ?? 0);
        $deviceType = in_array($data['device_type'] ?? '', ['server', 'hub_sw']) ? $data['device_type'] : null;
        $name       = trim($data['name'] ?? '');
        $ports      = intval($data['ports'] ?? 0);
        $fiberPorts = intval($data['fiber_ports'] ?? 0);
        $unitSize   = max(1, min(10, intval($data['unit_size'] ?? 1)));
        $position   = isset($data['position_in_rack']) && $data['position_in_rack'] !== '' ? intval($data['position_in_rack']) : null;
        $notes      = trim($data['notes'] ?? '');

        if (!$rackId)     throw new Exception("Geçerli bir rack seçin");
        if (!$deviceType) throw new Exception("Cihaz tipi (server / hub_sw) zorunludur");
        if (!$name)       throw new Exception("Cihaz adı boş olamaz");
        if ($position === null) throw new Exception("Slot Pozisyonu zorunludur");

        if ($id > 0) {
            $stmt = $conn->prepare("UPDATE rack_devices SET rack_id=?, device_type=?, name=?, ports=?, fiber_ports=?, unit_size=?, position_in_rack=?, notes=? WHERE id=?");
            $stmt->bind_param("issiiiisi", $rackId, $deviceType, $name, $ports, $fiberPorts, $unitSize, $position, $notes, $id);
        } else {
            $stmt = $conn->prepare("INSERT INTO rack_devices (rack_id, device_type, name, ports, fiber_ports, unit_size, position_in_rack, notes) VALUES (?,?,?,?,?,?,?,?)");
            $stmt->bind_param("issiiiis", $rackId, $deviceType, $name, $ports, $fiberPorts, $unitSize, $position, $notes);
        }
        if (!$stmt->execute()) throw new Exception("Kayıt hatası: " . $stmt->error);
        $newId = $id > 0 ? $id : $conn->insert_id;
        $stmt->close();

        echo json_encode(['success' => true, 'id' => $newId, 'message' => 'Kaydedildi']);
        exit;
    }

    echo json_encode(['success' => false, 'error' => 'Geçersiz istek metodu']);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
$conn->close();
?>
