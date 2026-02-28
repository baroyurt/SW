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
    $panelType = isset($data['panelType']) ? trim($data['panelType']) : '';
    $panelPort = isset($data['panelPort']) ? intval($data['panelPort']) : 0;
    $switchId = isset($data['switchId']) ? intval($data['switchId']) : 0;
    $switchPort = isset($data['switchPort']) ? intval($data['switchPort']) : 0;
    
    if ($panelId <= 0 || $panelPort <= 0 || $switchId <= 0 || $switchPort <= 0) {
        throw new Exception("Geçersiz panel veya switch bilgisi");
    }
    
    if (!in_array($panelType, ['patch', 'fiber'])) {
        throw new Exception("Geçersiz panel tipi");
    }
    
    // Switch bilgisini al
    $switchStmt = $conn->prepare("SELECT s.*, r.name as rack_name FROM switches s LEFT JOIN racks r ON s.rack_id = r.id WHERE s.id = ?");
    $switchStmt->bind_param("i", $switchId);
    $switchStmt->execute();
    $switchResult = $switchStmt->get_result();
    $switch = $switchResult->fetch_assoc();
    $switchStmt->close();
    
    if (!$switch) {
        throw new Exception("Switch bulunamadı");
    }
    
    // Panel bilgisini al
    if ($panelType === 'patch') {
        $panelStmt = $conn->prepare("SELECT pp.*, r.name as rack_name FROM patch_panels pp LEFT JOIN racks r ON pp.rack_id = r.id WHERE pp.id = ?");
    } else {
        $panelStmt = $conn->prepare("SELECT fp.*, r.name as rack_name FROM fiber_panels fp LEFT JOIN racks r ON fp.rack_id = r.id WHERE fp.id = ?");
    }
    $panelStmt->bind_param("i", $panelId);
    $panelStmt->execute();
    $panelResult = $panelStmt->get_result();
    $panel = $panelResult->fetch_assoc(); // DÜZELTME: $panel eklendi
    $panelStmt->close();
    
    if (!$panel) { // DÜZELTME: !$panel olarak değiştirildi
        throw new Exception("Panel bulunamadı");
    }
    
    // Aynı rack'te mi kontrol et
    if ($panel['rack_id'] != $switch['rack_id']) {
        throw new Exception("Panel ve switch farklı rack'lerde");
    }
    
    // Fiber kuralları kontrolü
    $totalPorts = $switch['ports'] ?? 48;
    $isFiberPort = $switchPort > ($totalPorts - 4);
    
    if ($panelType === 'fiber' && !$isFiberPort) {
        throw new Exception("Fiber paneller sadece fiber portlara bağlanabilir");
    }
    
    if ($panelType === 'patch' && $isFiberPort) {
        throw new Exception("Patch paneller fiber portlara bağlanamaz");
    }
    
    // Transaction başlat
    $conn->begin_transaction();
    
    try {
        // 1. Switch portundaki mevcut verileri al
        $portDataStmt = $conn->prepare("SELECT * FROM ports WHERE switch_id = ? AND port_no = ?");
        $portDataStmt->bind_param("ii", $switchId, $switchPort);
        $portDataStmt->execute();
        $portDataResult = $portDataStmt->get_result();
        $portData = $portDataResult->fetch_assoc();
        $portDataStmt->close();
        
        // 2. Switch portunu güncelle
        if ($portData) {
            $updatePortStmt = $conn->prepare("
                UPDATE ports 
                SET connected_panel_id = ?,
                    connected_panel_port = ?,
                    updated_at = NOW()
                WHERE switch_id = ? AND port_no = ?
            ");
            $updatePortStmt->bind_param("iiii", $panelId, $panelPort, $switchId, $switchPort);
            $updatePortStmt->execute();
            $updatePortStmt->close();
        } else {
            // Port yoksa oluştur
            $insertPortStmt = $conn->prepare("
                INSERT INTO ports (switch_id, port_no, type, device, ip, mac, connected_panel_id, connected_panel_port)
                VALUES (?, ?, 'ETHERNET', '', '', '', ?, ?)
            ");
            $insertPortStmt->bind_param("iiii", $switchId, $switchPort, $panelId, $panelPort);
            $insertPortStmt->execute();
            $insertPortStmt->close();
            
            // Yeni oluşturulan port verisini al
            $portDataStmt2 = $conn->prepare("SELECT * FROM ports WHERE switch_id = ? AND port_no = ?");
            $portDataStmt2->bind_param("ii", $switchId, $switchPort);
            $portDataStmt2->execute();
            $portDataResult2 = $portDataStmt2->get_result();
            $portData = $portDataResult2->fetch_assoc();
            $portDataStmt2->close();
        }
        
        // 3. Panel portunu güncelle
        $connectedTo = "Switch: {$switch['name']} Port {$switchPort}";
        if ($portData && isset($portData['device']) && !empty($portData['device'])) {
            $connectedTo .= " - " . $portData['device'];
        }
        
        $connectionDetails = json_encode([
            'switch_id' => $switchId,
            'switch_name' => $switch['name'],
            'switch_port' => $switchPort,
            'device' => $portData['device'] ?? '',
            'ip' => $portData['ip'] ?? '',
            'mac' => $portData['mac'] ?? '',
            'type' => $portData['type'] ?? '',
            'connection_info' => $portData['connection_info'] ?? '',
            'synced_at' => date('Y-m-d H:i:s'),
            'synced_from' => 'panel'
        ], JSON_UNESCAPED_UNICODE);
        
        if ($panelType === 'patch') {
            // Patch port kontrolü
            $checkPatchStmt = $conn->prepare("SELECT id FROM patch_ports WHERE panel_id = ? AND port_number = ?");
            $checkPatchStmt->bind_param("ii", $panelId, $panelPort);
            $checkPatchStmt->execute();
            $checkPatchResult = $checkPatchStmt->get_result();
            $patchExists = $checkPatchResult->num_rows > 0;
            $checkPatchStmt->close();
            
            if ($patchExists) {
                $updatePatchStmt = $conn->prepare("
                    UPDATE patch_ports 
                    SET status = 'active',
                        connection_info_preserved = ?,
                        connected_switch_id = ?,
                        connected_switch_port = ?,
                        connection_details = ?
                    WHERE panel_id = ? AND port_number = ?
                ");
                $updatePatchStmt->bind_param("siisii", $connectedTo, $switchId, $switchPort, $connectionDetails, $panelId, $panelPort);
                $updatePatchStmt->execute();
                $updatePatchStmt->close();
            } else {
                $insertPatchStmt = $conn->prepare("
                    INSERT INTO patch_ports (panel_id, port_number, status, connection_info_preserved, connected_switch_id, connected_switch_port, connection_details)
                    VALUES (?, ?, 'active', ?, ?, ?, ?)
                ");
                $insertPatchStmt->bind_param("iisiis", $panelId, $panelPort, $connectedTo, $switchId, $switchPort, $connectionDetails);
                $insertPatchStmt->execute();
                $insertPatchStmt->close();
            }
        } else {
            // Fiber port kontrolü
            $checkFiberStmt = $conn->prepare("SELECT id FROM fiber_ports WHERE panel_id = ? AND port_number = ?");
            $checkFiberStmt->bind_param("ii", $panelId, $panelPort);
            $checkFiberStmt->execute();
            $checkFiberResult = $checkFiberStmt->get_result();
            $fiberExists = $checkFiberResult->num_rows > 0;
            $checkFiberStmt->close();
            
            if ($fiberExists) {
                $updateFiberStmt = $conn->prepare("
                    UPDATE fiber_ports 
                    SET status = 'active',
                        connection_info_preserved = ?,
                        connected_switch_id = ?,
                        connected_switch_port = ?,
                        connection_type = 'switch_fiber',
                        connection_details = ?
                    WHERE panel_id = ? AND port_number = ?
                ");
                $updateFiberStmt->bind_param("siisii", $connectedTo, $switchId, $switchPort, $connectionDetails, $panelId, $panelPort);
                $updateFiberStmt->execute();
                $updateFiberStmt->close();
            } else {
                $insertFiberStmt = $conn->prepare("
                    INSERT INTO fiber_ports (panel_id, port_number, status, connection_info_preserved, connected_switch_id, connected_switch_port, connection_type, connection_details)
                    VALUES (?, ?, 'active', ?, ?, ?, 'switch_fiber', ?)
                ");
                $insertFiberStmt->bind_param("iisiis", $panelId, $panelPort, $connectedTo, $switchId, $switchPort, $connectionDetails);
                $insertFiberStmt->execute();
                $insertFiberStmt->close();
            }
        }
        
        $conn->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Panel ve switch bağlantısı senkronize edildi',
            'data' => [
                'panel_id' => $panelId,
                'panel_type' => $panelType,
                'panel_port' => $panelPort,
                'switch_id' => $switchId,
                'switch_port' => $switchPort
            ]
        ]);
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
    
} catch (Exception $e) {
    error_log("Panel-Switch connection error: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}

$conn->close();
?>