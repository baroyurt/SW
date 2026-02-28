<?php
include "db.php";

header('Content-Type: application/json; charset=utf-8');

try {
    $type = isset($_GET['type']) ? $_GET['type'] : '';
    $id = isset($_GET['id']) ? intval($_GET['id']) : 0;
    
    if (!$type || $id <= 0) {
        throw new Exception("Geçersiz istek parametreleri");
    }
    
    // Tablo eşleştirmesi
    $tables = [
        "rack" => "racks",
        "switch" => "switches",
        "port" => "ports",
        "patch_panel" => "patch_panels",
        "fiber_panel" => "fiber_panels"
    ];
    
    if (!isset($tables[$type])) {
        throw new Exception("Geçersiz silme türü");
    }
    
    $tableName = $tables[$type];
    
    // Özel kontroller
    if ($type === 'patch_panel') {
        // Patch paneli silmeden önce portlarını da sil ve switch.portlardaki connected referanslarını temizle
        $conn->begin_transaction();
        try {
            // 1) Patc_portları sil
            $deletePortsStmt = $conn->prepare("DELETE FROM patch_ports WHERE panel_id = ?");
            $deletePortsStmt->bind_param("i", $id);
            $deletePortsStmt->execute();
            $deletePortsStmt->close();
            
            // 2) Switch portlarında bu panel referansını temizle
            $clearSwitchPortsStmt = $conn->prepare("
                UPDATE ports 
                SET connected_panel_id = NULL,
                    connected_panel_port = NULL,
                    updated_at = NOW()
                WHERE connected_panel_id = ?
            ");
            $clearSwitchPortsStmt->bind_param("i", $id);
            $clearSwitchPortsStmt->execute();
            $clearSwitchPortsStmt->close();
            
            // 3) Panel kaydını sil
            $stmt = $conn->prepare("DELETE FROM {$tableName} WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $affectedRows = $stmt->affected_rows;
            $stmt->close();
            
            $conn->commit();
            
            echo json_encode([
                "status" => "deleted",
                "message" => "Patch panel ve ilişkili veriler silindi",
                "affected_rows" => $affectedRows
            ]);
            $conn->close();
            exit;
        } catch (Exception $e) {
            $conn->rollback();
            throw $e;
        }
    }
    
    if ($type === 'fiber_panel') {
        // Fiber paneli silmeden önce fiber_ports'u netleştir / (ON DELETE CASCADE DB'de varsa bu adım güvenlik amaçlı)
        $conn->begin_transaction();
        try {
            // 1) Fiber portları sil (FK varsa cascade ile otomatik olabilir, ama güvenli olarak sil)
            $deleteFiberPorts = $conn->prepare("DELETE FROM fiber_ports WHERE panel_id = ?");
            $deleteFiberPorts->bind_param("i", $id);
            $deleteFiberPorts->execute();
            $deleteFiberPorts->close();
            
            // 2) Panel kaydını sil
            $stmt = $conn->prepare("DELETE FROM {$tableName} WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $affectedRows = $stmt->affected_rows;
            $stmt->close();
            
            $conn->commit();
            
            echo json_encode([
                "status" => "deleted",
                "message" => "Fiber panel ve ilişkili fiber portlar silindi",
                "affected_rows" => $affectedRows
            ]);
            $conn->close();
            exit;
        } catch (Exception $e) {
            $conn->rollback();
            throw $e;
        }
    }
    
    // Diğer tipler için standart silme
    $stmt = $conn->prepare("DELETE FROM {$tableName} WHERE id = ?");
    $stmt->bind_param("i", $id);
    
    if ($stmt->execute()) {
        $affectedRows = $stmt->affected_rows;
        $stmt->close();
        
        echo json_encode([
            "status" => "deleted",
            "message" => "Silme işlemi başarılı",
            "affected_rows" => $affectedRows
        ]);
    } else {
        throw new Exception("Silme işlemi başarısız: " . $stmt->error);
    }
    
} catch (Exception $e) {
    echo json_encode([
        "status" => "error",
        "message" => $e->getMessage()
    ]);
}

$conn->close();
?>