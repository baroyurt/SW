<?php
include "db.php";

header('Content-Type: application/json; charset=utf-8');

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', 'port_panel_sync.log');

try {
    $input = file_get_contents("php://input");
    $data = json_decode($input, true);
    
    if (!$data) {
        throw new Exception("Geçersiz veri");
    }
    
    $switchId = isset($data['switchId']) ? intval($data['switchId']) : 0;
    $portNo = isset($data['port']) ? intval($data['port']) : 0;
    $type = isset($data['type']) ? trim($data['type']) : '';
    $device = isset($data['device']) ? trim($data['device']) : '';
    $ip = isset($data['ip']) ? trim($data['ip']) : '';
    $mac = isset($data['mac']) ? trim($data['mac']) : '';
    
    // Panel bağlantı bilgileri
    $panelId = isset($data['panelId']) ? intval($data['panelId']) : null;
    $panelPort = isset($data['panelPort']) ? intval($data['panelPort']) : null;
    $panelType = isset($data['panelType']) ? trim($data['panelType']) : 'patch';
    
    // Connection info (önemli!)
    $connectionInfo = isset($data['connectionInfo']) ? $data['connectionInfo'] : '';
    
    if ($switchId <= 0 || $portNo <= 0) {
        throw new Exception("Geçersiz switch veya port numarası");
    }
    
    // Switch bilgisini al
    $switchStmt = $conn->prepare("SELECT s.*, r.id as rack_id, r.name as rack_name FROM switches s LEFT JOIN racks r ON s.rack_id = r.id WHERE s.id = ?");
    $switchStmt->bind_param("i", $switchId);
    $switchStmt->execute();
    $switchResult = $switchStmt->get_result();
    $switch = $switchResult->fetch_assoc();
    $switchStmt->close();
    
    if (!$switch) {
        throw new Exception("Switch bulunamadı");
    }
    
    // Port fiber mi kontrol et
    $isFiberPort = $portNo > ($switch['ports'] - 4);
    
    // Panel bağlantısı varsa validasyon
    if ($panelId && $panelPort) {
        // Panel'in aynı rack'te olup olmadığını kontrol et
        if ($panelType === 'patch') {
            $panelCheckStmt = $conn->prepare("SELECT rack_id, panel_letter FROM patch_panels WHERE id = ?");
        } else {
            $panelCheckStmt = $conn->prepare("SELECT rack_id, panel_letter FROM fiber_panels WHERE id = ?");
        }
        $panelCheckStmt->bind_param("i", $panelId);
        $panelCheckStmt->execute();
        $panelCheckResult = $panelCheckStmt->get_result();
        $panelInfo = $panelCheckResult->fetch_assoc();
        $panelCheckStmt->close();
        
        if (!$panelInfo) {
            throw new Exception("Panel bulunamadı");
        }
        
        if ($panelInfo['rack_id'] != $switch['rack_id']) {
            throw new Exception("Panel bu switch'in bulunduğu rack'te değil");
        }
        
        // Fiber kuralları kontrolü
        if ($panelType === 'fiber' && !$isFiberPort) {
            throw new Exception("Fiber panel sadece fiber portlara bağlanabilir");
        }
        
        if ($panelType === 'patch' && $isFiberPort) {
            throw new Exception("Patch panel fiber portlara bağlanamaz");
        }
    }
    
    // Transaction başlat
    $conn->begin_transaction();
    
    try {
        // connected_to değeri hazırla
        $connectedTo = null;
        if ($panelId && $panelPort) {
            // Panel bağlantısı varsa
            $panelLetter = $panelInfo['panel_letter'];
            $connectedTo = "{$switch['rack_name']}-{$panelLetter}{$panelPort}";
        }
        
        // 1. Switch portunu güncelle/ekle
        $portCheckStmt = $conn->prepare("SELECT id FROM ports WHERE switch_id = ? AND port_no = ?");
        $portCheckStmt->bind_param("ii", $switchId, $portNo);
        $portCheckStmt->execute();
        $portCheckResult = $portCheckStmt->get_result();
        $portExists = $portCheckResult->num_rows > 0;
        $portCheckStmt->close();
        
        if ($portExists) {
            // Güncelle
            $updatePortStmt = $conn->prepare("
                UPDATE ports 
                SET type = ?, 
                    device = ?, 
                    ip = ?, 
                    mac = ?,
                    connected_panel_id = ?,
                    connected_panel_port = ?,
                    connected_to = ?,
                    connection_info_preserved = ?,
                    updated_at = NOW()
                WHERE switch_id = ? AND port_no = ?
            ");
            
            $updatePortStmt->bind_param("ssssiiisii", 
                $type, $device, $ip, $mac,
                $panelId, $panelPort, $connectedTo, $connectionInfo,
                $switchId, $portNo
            );
            
            if (!$updatePortStmt->execute()) {
                throw new Exception("Port güncellenemedi: " . $updatePortStmt->error);
            }
            $updatePortStmt->close();
        } else {
            // Ekle
            $insertPortStmt = $conn->prepare("
                INSERT INTO ports (switch_id, port_no, type, device, ip, mac, connected_panel_id, connected_panel_port, connected_to, connection_info_preserved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $insertPortStmt->bind_param("iissssiiis", 
                $switchId, $portNo, $type, $device, $ip, $mac,
                $panelId, $panelPort, $connectedTo, $connectionInfo
            );
            
            if (!$insertPortStmt->execute()) {
                throw new Exception("Port eklenemedi: " . $insertPortStmt->error);
            }
            $insertPortStmt->close();
        }
        
        // 2. Panel portunu senkronize et (eğer panel bağlantısı varsa)
        if ($panelId && $panelPort) {
            // Connection bilgisi hazırla
            $panelConnectedTo = $device;
            if ($ip) $panelConnectedTo .= " ($ip)";
            if ($mac) $panelConnectedTo .= " [$mac]";
            
            $connectionDetails = json_encode([
                'switch_id' => $switchId,
                'switch_name' => $switch['name'],
                'switch_port' => $portNo,
                'device' => $device,
                'ip' => $ip,
                'mac' => $mac,
                'type' => $type,
                'connection_info' => $connectionInfo,
                'synced_at' => date('Y-m-d H:i:s')
            ], JSON_UNESCAPED_UNICODE);
            
            if ($panelType === 'patch') {
                // Patch port kontrolü
                $patchPortCheckStmt = $conn->prepare("SELECT id FROM patch_ports WHERE panel_id = ? AND port_number = ?");
                $patchPortCheckStmt->bind_param("ii", $panelId, $panelPort);
                $patchPortCheckStmt->execute();
                $patchPortCheckResult = $patchPortCheckStmt->get_result();
                $patchPortExists = $patchPortCheckResult->num_rows > 0;
                $patchPortCheckStmt->close();
                
                if ($patchPortExists) {
                    // Patch port güncelle
                    $updatePatchStmt = $conn->prepare("
                        UPDATE patch_ports 
                        SET status = 'active',
                            connected_to = ?,
                            connected_switch_id = ?,
                            connected_switch_port = ?,
                            connection_details = ?
                        WHERE panel_id = ? AND port_number = ?
                    ");
                    
                    $updatePatchStmt->bind_param("siisii", 
                        $panelConnectedTo, $switchId, $portNo, $connectionDetails,
                        $panelId, $panelPort
                    );
                    
                    if (!$updatePatchStmt->execute()) {
                        throw new Exception("Patch port güncellenemedi: " . $updatePatchStmt->error);
                    }
                    $updatePatchStmt->close();
                } else {
                    // Patch port ekle
                    $insertPatchStmt = $conn->prepare("
                        INSERT INTO patch_ports (panel_id, port_number, status, connected_to, connected_switch_id, connected_switch_port, connection_details)
                        VALUES (?, ?, 'active', ?, ?, ?, ?)
                    ");
                    
                    $insertPatchStmt->bind_param("iisiis", 
                        $panelId, $panelPort, $panelConnectedTo, $switchId, $portNo, $connectionDetails
                    );
                    
                    if (!$insertPatchStmt->execute()) {
                        throw new Exception("Patch port eklenemedi: " . $insertPatchStmt->error);
                    }
                    $insertPatchStmt->close();
                }
                
            } else if ($panelType === 'fiber') {
                // Fiber port kontrolü
                $fiberPortCheckStmt = $conn->prepare("SELECT id FROM fiber_ports WHERE panel_id = ? AND port_number = ?");
                $fiberPortCheckStmt->bind_param("ii", $panelId, $panelPort);
                $fiberPortCheckStmt->execute();
                $fiberPortCheckResult = $fiberPortCheckStmt->get_result();
                $fiberPortExists = $fiberPortCheckResult->num_rows > 0;
                $fiberPortCheckStmt->close();
                
                if ($fiberPortExists) {
                    // Fiber port güncelle
                    $updateFiberStmt = $conn->prepare("
                        UPDATE fiber_ports 
                        SET status = 'active',
                            connected_to = ?,
                            connected_switch_id = ?,
                            connected_switch_port = ?,
                            connection_type = 'switch_fiber',
                            connection_details = ?
                        WHERE panel_id = ? AND port_number = ?
                    ");
                    
                    $updateFiberStmt->bind_param("siisii", 
                        $panelConnectedTo, $switchId, $portNo, $connectionDetails,
                        $panelId, $panelPort
                    );
                    
                    if (!$updateFiberStmt->execute()) {
                        throw new Exception("Fiber port güncellenemedi: " . $updateFiberStmt->error);
                    }
                    $updateFiberStmt->close();
                } else {
                    // Fiber port ekle
                    $insertFiberStmt = $conn->prepare("
                        INSERT INTO fiber_ports (panel_id, port_number, status, connected_to, connected_switch_id, connected_switch_port, connection_type, connection_details)
                        VALUES (?, ?, 'active', ?, ?, ?, 'switch_fiber', ?)
                    ");
                    
                    $insertFiberStmt->bind_param("iisiis", 
                        $panelId, $panelPort, $panelConnectedTo, $switchId, $portNo, $connectionDetails
                    );
                    
                    if (!$insertFiberStmt->execute()) {
                        throw new Exception("Fiber port eklenemedi: " . $insertFiberStmt->error);
                    }
                    $insertFiberStmt->close();
                }
            }
            
            // 3. Bağlantı geçmişine kaydet
            $historyStmt = $conn->prepare("
                INSERT INTO connection_history (connection_type, source_type, source_id, source_port, target_type, target_id, target_port, action, new_values)
                VALUES (?, 'switch', ?, ?, ?, ?, ?, 'created', ?)
            ");
            
            $connectionType = $panelType === 'patch' ? 'switch_to_patch' : 'switch_to_fiber';
            $historyStmt->bind_param("siisiis",
    $connectionType,
    $switchId,
    $portNo,
    $panelType,
    $panelId,
    $panelPort,
    $connectionDetails
);
            $historyStmt->execute();
            $historyStmt->close();
        }
        
        $conn->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Port ve panel bağlantısı başarıyla güncellendi',
            'data' => [
                'switch_id' => $switchId,
                'port_no' => $portNo,
                'panel_id' => $panelId,
                'panel_port' => $panelPort,
                'panel_type' => $panelType,
                'synced' => true
            ]
        ]);
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
    
} catch (Exception $e) {
    error_log("Port-Panel sync error: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}

$conn->close();
?>