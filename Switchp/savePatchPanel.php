<?php
include "db.php";

header('Content-Type: application/json; charset=utf-8');

$data = json_decode(file_get_contents("php://input"), true);

if (!$data) {
    die(json_encode(["success" => false, "error" => "Geçersiz veri"]));
}

try {
    $rackId = intval($data['rackId'] ?? 0);
    $panelLetter = strtoupper(trim($data['panelLetter'] ?? ''));
    $totalPorts = intval($data['totalPorts'] ?? 0);
    $positionInRack = intval($data['positionInRack'] ?? 0);
    $description = isset($data['description']) ? trim($data['description']) : '';

    // ── Delete action ─────────────────────────────────────────────────────
    if (isset($data['action']) && $data['action'] === 'delete') {
        $delId = intval($data['id'] ?? 0);
        $delType = $data['type'] ?? 'patch';
        if ($delId <= 0) throw new Exception("Geçersiz panel ID");
        if ($delType === 'fiber') {
            $s = $conn->prepare("DELETE FROM fiber_panels WHERE id = ?");
        } else {
            $s = $conn->prepare("DELETE FROM patch_panels WHERE id = ?");
        }
        $s->bind_param("i", $delId);
        if ($s->execute()) { $s->close(); echo json_encode(["success" => true, "message" => "Panel silindi"]); exit; }
        else { $s->close(); throw new Exception("Panel silinemedi: " . $conn->error); }
    }

    // ── Edit action (rack / slot change) ──────────────────────────────────
    if (isset($data['action']) && $data['action'] === 'edit') {
        $editId   = intval($data['id'] ?? 0);
        $editType = $data['type'] ?? 'patch';
        if ($editId <= 0) throw new Exception("Geçersiz panel ID");
        if ($rackId <= 0) throw new Exception("Geçerli bir rack seçmelisiniz");

        // Slot çakışma kontrolü (kendi slotunu hariç tut)
        if ($positionInRack > 0) {
            $chk = $conn->prepare("
                SELECT id FROM switches WHERE rack_id = ? AND position_in_rack = ?
                UNION
                SELECT id FROM patch_panels WHERE rack_id = ? AND position_in_rack = ? AND id != ?
                UNION
                SELECT id FROM fiber_panels WHERE rack_id = ? AND position_in_rack = ? AND id != ?
            ");
            $excPatch = $editType === 'patch' ? $editId : 0;
            $excFiber = $editType === 'fiber' ? $editId : 0;
            $chk->bind_param("iiiiiiii", $rackId, $positionInRack, $rackId, $positionInRack, $excPatch, $rackId, $positionInRack, $excFiber);
            $chk->execute();
            if ($chk->get_result()->num_rows > 0) { $chk->close(); throw new Exception("Slot {$positionInRack} zaten dolu"); }
            $chk->close();
        }

        if ($editType === 'fiber') {
            $u = $conn->prepare("UPDATE fiber_panels SET rack_id = ?, position_in_rack = ? WHERE id = ?");
        } else {
            $u = $conn->prepare("UPDATE patch_panels SET rack_id = ?, position_in_rack = ? WHERE id = ?");
        }
        $u->bind_param("iii", $rackId, $positionInRack, $editId);
        if ($u->execute()) { $u->close(); echo json_encode(["success" => true, "message" => "Panel güncellendi"]); exit; }
        else { $u->close(); throw new Exception("Panel güncellenemedi: " . $conn->error); }
    }

    // ── Insert new patch panel ────────────────────────────────────────────
    
    // Aynı rack'ta aynı harfte panel var mı kontrol et
    $checkStmt = $conn->prepare("
        SELECT id FROM patch_panels 
        WHERE rack_id = ? AND panel_letter = ?
    ");
    $checkStmt->bind_param("is", $rackId, $panelLetter);
    $checkStmt->execute();
    $checkResult = $checkStmt->get_result();
    
    if ($checkResult->num_rows > 0) {
        throw new Exception("Bu rack'te $panelLetter paneli zaten mevcut");
    }
    
    // Aynı pozisyonda başka bir şey var mı kontrol et
    if ($positionInRack > 0) {
        $checkPosStmt = $conn->prepare("
            SELECT id FROM patch_panels 
            WHERE rack_id = ? AND position_in_rack = ?
            UNION
            SELECT id FROM switches 
            WHERE rack_id = ? AND position_in_rack = ?
        ");
        $checkPosStmt->bind_param("iiii", $rackId, $positionInRack, $rackId, $positionInRack);
        $checkPosStmt->execute();
        $checkPosResult = $checkPosStmt->get_result();
        
        if ($checkPosResult->num_rows > 0) {
            throw new Exception("Bu slot zaten dolu");
        }
    }
    
    // Panel ekle
    $insertStmt = $conn->prepare("
        INSERT INTO patch_panels (rack_id, panel_letter, total_ports, description, position_in_rack)
        VALUES (?, ?, ?, ?, ?)
    ");
    $insertStmt->bind_param("isisi", $rackId, $panelLetter, $totalPorts, $description, $positionInRack);
    
    if ($insertStmt->execute()) {
        $panelId = $conn->insert_id;
        
        // Panel portlarını oluştur
        $portStmt = $conn->prepare("
            INSERT INTO patch_ports (panel_id, port_number, status)
            VALUES (?, ?, 'inactive')
        ");
        
        for ($portNo = 1; $portNo <= $totalPorts; $portNo++) {
            $portStmt->bind_param("ii", $panelId, $portNo);
            $portStmt->execute();
        }
        $portStmt->close();
        
        echo json_encode([
            "success" => true,
            "panelId" => $panelId,
            "message" => "Patch panel ve portları oluşturuldu"
        ]);
    } else {
        throw new Exception("Panel ekleme hatası: " . $insertStmt->error);
    }
    
    $insertStmt->close();
    
} catch (Exception $e) {
    echo json_encode(["success" => false, "error" => $e->getMessage()]);
}

$conn->close();
?>