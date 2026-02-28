<?php
include "db.php";

header('Content-Type: application/json; charset=utf-8');

$data = json_decode(file_get_contents("php://input"), true);

if (!$data) {
    die(json_encode(["success" => false, "error" => "Geçersiz veri"]));
}

try {
    // Delete action
    if (isset($data['action']) && $data['action'] === 'delete') {
        $delId = isset($data['id']) ? intval($data['id']) : 0;
        if ($delId <= 0) throw new Exception("Geçersiz switch ID");
        $delStmt = $conn->prepare("DELETE FROM switches WHERE id = ?");
        $delStmt->bind_param("i", $delId);
        if ($delStmt->execute()) { $delStmt->close(); echo json_encode(["success" => true, "message" => "Switch silindi"]); exit; }
        else { $delStmt->close(); throw new Exception("Switch silinemedi: " . $conn->error); }
    }

    $rackId = isset($data['rackId']) ? intval($data['rackId']) : 0;
    $positionInRack = isset($data['positionInRack']) ? intval($data['positionInRack']) : null;
    $isUpdate = isset($data['id']) && !empty($data['id']) && $data['id'] > 0;
    
    // Rack kontrolü
    if ($rackId <= 0) {
        throw new Exception("Geçerli bir rack seçmelisiniz");
    }
    
    // Position kontrolü - sadece position verilmişse
    if ($positionInRack !== null && $positionInRack > 0) {
        // Aynı pozisyonda başka bir şey var mı kontrol et
        // COLLATION uyuşmazlığını çözmek için explicit CAST kullanıyoruz
        
        $checkPosStmt = $conn->prepare("
            SELECT id, 'switch' as type, CAST(name AS CHAR) as name 
            FROM switches 
            WHERE rack_id = ? AND position_in_rack = ? AND id != ?
            UNION
            SELECT id, 'panel' as type, CAST(panel_letter AS CHAR) as name 
            FROM patch_panels 
            WHERE rack_id = ? AND position_in_rack = ?
        ");
        
        $checkId = $isUpdate ? intval($data['id']) : 0;
        $checkPosStmt->bind_param("iiiii", $rackId, $positionInRack, $checkId, $rackId, $positionInRack);
        $checkPosStmt->execute();
        $checkResult = $checkPosStmt->get_result();
        
        if ($checkResult->num_rows > 0) {
            $conflict = $checkResult->fetch_assoc();
            $conflictType = $conflict['type'] === 'switch' ? 'Switch' : 'Patch Panel';
            throw new Exception("Slot {$positionInRack} zaten dolu ({$conflictType}: {$conflict['name']})");
        }
        $checkPosStmt->close();
    }
    
    if ($isUpdate) {
        // Güncelleme
        $stmt = $conn->prepare("
            UPDATE switches 
            SET name = ?, brand = ?, model = ?, ports = ?, status = ?, rack_id = ?, ip = ?, position_in_rack = ?
            WHERE id = ?
        ");
        
        $stmt->bind_param(
            "sssissiii",
            $data['name'],
            $data['brand'],
            $data['model'],
            $data['ports'],
            $data['status'],
            $rackId,
            $data['ip'],
            $positionInRack,
            $data['id']
        );
        
        if ($stmt->execute()) {
            $newSwitchId = $data['id'];
            
            // Sadece port sayısı değişmişse portları yönet
            $checkPortsStmt = $conn->prepare("SELECT COUNT(*) as count FROM ports WHERE switch_id = ?");
            $checkPortsStmt->bind_param("i", $newSwitchId);
            $checkPortsStmt->execute();
            $portCountResult = $checkPortsStmt->get_result();
            $currentPortCount = $portCountResult->fetch_assoc()['count'];
            $checkPortsStmt->close();
            
            if ($currentPortCount != $data['ports']) {
                // Port sayısı değişti, portları yeniden yönet
                // Ancak bu sefer mevcut port bilgilerini koruyalım
                manageSwitchPortsAdvanced($conn, $newSwitchId, $data['ports']);
            }
            
            echo json_encode([
                "success" => true, 
                "status" => "ok", 
                "rackId" => $rackId,
                "switchId" => $newSwitchId,
                "message" => "Switch güncellendi"
            ]);
        } else {
            throw new Exception("Switch güncelleme hatası: " . $stmt->error);
        }
        
        $stmt->close();
        
    } else {
        // Yeni ekleme
        
        // Aynı isimde switch var mı kontrol et
        $checkNameStmt = $conn->prepare("SELECT id FROM switches WHERE name = ?");
        $checkNameStmt->bind_param("s", $data['name']);
        $checkNameStmt->execute();
        $nameResult = $checkNameStmt->get_result();
        
        if ($nameResult->num_rows > 0) {
            throw new Exception("Bu isimde bir switch zaten var: " . $data['name']);
        }
        $checkNameStmt->close();
        
        $stmt = $conn->prepare("
            INSERT INTO switches (name, brand, model, ports, status, rack_id, ip, position_in_rack)
            VALUES (?,?,?,?,?,?,?,?)
        ");
        
        $stmt->bind_param(
            "sssissii",
            $data['name'],
            $data['brand'],
            $data['model'],
            $data['ports'],
            $data['status'],
            $rackId,
            $data['ip'],
            $positionInRack
        );
        
        if ($stmt->execute()) {
            $newSwitchId = $conn->insert_id;
            
            // Switch oluşturulduktan sonra portları yönet
            manageSwitchPorts($conn, $newSwitchId, $data['ports']);
            
            echo json_encode([
                "success" => true, 
                "status" => "ok", 
                "rackId" => $rackId,
                "switchId" => $newSwitchId,
                "message" => "Switch başarıyla eklendi"
            ]);
        } else {
            throw new Exception("Switch ekleme hatası: " . $stmt->error);
        }
        
        $stmt->close();
    }
    
} catch (Exception $e) {
    echo json_encode([
        "success" => false, 
        "error" => $e->getMessage()
    ]);
}

$conn->close();

// Switch portlarını yöneten fonksiyon (yeni ekleme için)
function manageSwitchPorts($conn, $switchId, $totalPorts) {
    // Önce mevcut portları temizle (yeni switch için)
    $deleteStmt = $conn->prepare("DELETE FROM ports WHERE switch_id = ?");
    $deleteStmt->bind_param("i", $switchId);
    $deleteStmt->execute();
    $deleteStmt->close();
    
    // Tüm portları ekle - başlangıçta BOŞ
    $portStmt = $conn->prepare("
        INSERT INTO ports (switch_id, port_no, type, device, ip, mac)
        VALUES (?, ?, 'BOŞ', '', '', '')
    ");
    
    for ($portNo = 1; $portNo <= $totalPorts; $portNo++) {
        $portStmt->bind_param("ii", $switchId, $portNo);
        $portStmt->execute();
    }
    
    $portStmt->close();
    return true;
}

// Gelişmiş port yönetimi - mevcut bilgileri korur
function manageSwitchPortsAdvanced($conn, $switchId, $newTotalPorts) {
    // Mevcut portları ve bilgilerini al
    $currentPortsStmt = $conn->prepare("
        SELECT port_no, type, device, ip, mac
        FROM ports 
        WHERE switch_id = ? 
        ORDER BY port_no
    ");
    $currentPortsStmt->bind_param("i", $switchId);
    $currentPortsStmt->execute();
    $currentPortsResult = $currentPortsStmt->get_result();
    
    // Mevcut portları bir array'e kaydet
    $existingPorts = [];
    while ($port = $currentPortsResult->fetch_assoc()) {
        $existingPorts[$port['port_no']] = $port;
    }
    $currentPortsStmt->close();
    
    // Mevcut port sayısı
    $currentPortCount = count($existingPorts);
    
    // Port sayısı azaldı mı arttı mı?
    if ($newTotalPorts > $currentPortCount) {
        // Port sayısı arttı - ek portlar ekle
        for ($portNo = $currentPortCount + 1; $portNo <= $newTotalPorts; $portNo++) {
            // Yeni port ekle
            $insertStmt = $conn->prepare("
                INSERT INTO ports (switch_id, port_no, type, device, ip, mac)
                VALUES (?, ?, 'BOŞ', '', '', '')
            ");
            $insertStmt->bind_param("ii", $switchId, $portNo);
            $insertStmt->execute();
            $insertStmt->close();
        }
    } elseif ($newTotalPorts < $currentPortCount) {
        // Port sayısı azaldı - fazla portları sil
        $deleteStmt = $conn->prepare("DELETE FROM ports WHERE switch_id = ? AND port_no > ?");
        $deleteStmt->bind_param("ii", $switchId, $newTotalPorts);
        $deleteStmt->execute();
        $deleteStmt->close();
    }
    // Port sayısı aynı ise hiçbir şey yapma
    
    return true;
}
?>