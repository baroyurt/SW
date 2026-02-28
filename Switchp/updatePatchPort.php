<?php
include "db.php";

header('Content-Type: application/json; charset=utf-8');

try {
    $input = file_get_contents("php://input");
    $data = json_decode($input, true);
    
    if (!$data) {
        throw new Exception("Geçersiz veri");
    }
    
    $panelId = isset($data['panelId']) ? intval($data['panelId']) : 0;
    $portNumber = isset($data['portNumber']) ? intval($data['portNumber']) : 0;
    $connectedTo = isset($data['connectedTo']) ? trim($data['connectedTo']) : '';
    $status = isset($data['status']) ? trim($data['status']) : 'inactive';
    
    if ($panelId <= 0 || $portNumber <= 0) {
        throw new Exception("Geçersiz panel veya port numarası");
    }
    
    // Bu fonksiyon patch_ports tablosunu güncellemeli, ports tablosunu değil!
    // Patch port kontrol et
    $checkStmt = $conn->prepare("SELECT id FROM patch_ports WHERE panel_id = ? AND port_number = ?");
    $checkStmt->bind_param("ii", $panelId, $portNumber);
    $checkStmt->execute();
    $checkResult = $checkStmt->get_result();
    
    if ($checkResult->num_rows > 0) {
        // Güncelle
        $updateStmt = $conn->prepare("
            UPDATE patch_ports 
            SET status = ?, connection_info_preserved = ?
            WHERE panel_id = ? AND port_number = ?
        ");
        $updateStmt->bind_param("ssii", $status, $connectedTo, $panelId, $portNumber);
        
        if ($updateStmt->execute()) {
            echo json_encode([
                "success" => true,
                "message" => "Port güncellendi"
            ]);
        } else {
            throw new Exception("Port güncelleme hatası: " . $updateStmt->error);
        }
        $updateStmt->close();
    } else {
        // Yeni ekle
        $insertStmt = $conn->prepare("
            INSERT INTO patch_ports (panel_id, port_number, status, connection_info_preserved)
            VALUES (?, ?, ?, ?)
        ");
        $insertStmt->bind_param("iiss", $panelId, $portNumber, $status, $connectedTo);
        
        if ($insertStmt->execute()) {
            echo json_encode([
                "success" => true,
                "message" => "Port eklendi"
            ]);
        } else {
            throw new Exception("Port ekleme hatası: " . $insertStmt->error);
        }
        $insertStmt->close();
    }
    
    $checkStmt->close();
    
} catch (Exception $e) {
    echo json_encode([
        "success" => false,
        "error" => $e->getMessage()
    ]);
}

$conn->close();
?>