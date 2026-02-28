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
    $portNumber = isset($data['portNumber']) ? intval($data['portNumber']) : 0;
    
    if ($panelId <= 0 || $portNumber <= 0) {
        throw new Exception("Geçersiz panel veya port numarası");
    }
    
    if (!in_array($panelType, ['patch', 'fiber'])) {
        throw new Exception("Geçersiz panel tipi");
    }
    
    // Panel port bilgisini al
    if ($panelType === 'patch') {
        $portStmt = $conn->prepare("SELECT * FROM patch_ports WHERE panel_id = ? AND port_number = ?");
    } else {
        $portStmt = $conn->prepare("SELECT * FROM fiber_ports WHERE panel_id = ? AND port_number = ?");
    }
    $portStmt->bind_param("ii", $panelId, $portNumber);
    $portStmt->execute();
    $portResult = $portStmt->get_result();
    $panelPort = $portResult->fetch_assoc();
    $portStmt->close();
    
    if (!$panelPort) {
        throw new Exception("Panel port bulunamadı");
    }
    
    $connectedSwitchId = $panelPort['connected_switch_id'];
    $connectedSwitchPort = $panelPort['connected_switch_port'];
    
    // Transaction başlat
    $conn->begin_transaction();
    
    try {
        // 1. Panel portunu temizle
        if ($panelType === 'patch') {
            $updatePanelStmt = $conn->prepare("
                UPDATE patch_ports 
                SET status = 'inactive',
                    connected_to = NULL,
                    connected_switch_id = NULL,
                    connected_switch_port = NULL,
                    connection_details = NULL
                WHERE panel_id = ? AND port_number = ?
            ");
        } else {
            $updatePanelStmt = $conn->prepare("
                UPDATE fiber_ports 
                SET status = 'inactive',
                    connected_to = NULL,
                    connected_switch_id = NULL,
                    connected_switch_port = NULL,
                    connection_type = NULL,
                    connection_details = NULL
                WHERE panel_id = ? AND port_number = ?
            ");
        }
        $updatePanelStmt->bind_param("ii", $panelId, $portNumber);
        $updatePanelStmt->execute();
        $updatePanelStmt->close();
        
        // 2. Switch portundaki panel bağlantısını temizle
        if ($connectedSwitchId && $connectedSwitchPort) {
            $updateSwitchPortStmt = $conn->prepare("
                UPDATE ports 
                SET connected_panel_id = NULL,
                    connected_panel_port = NULL,
                    updated_at = NOW()
                WHERE switch_id = ? AND port_no = ?
            ");
            $updateSwitchPortStmt->bind_param("ii", $connectedSwitchId, $connectedSwitchPort);
            $updateSwitchPortStmt->execute();
            $updateSwitchPortStmt->close();
        }
        
        // 3. Bağlantı geçmişine kaydet
        if ($connectedSwitchId && $connectedSwitchPort) {
            $historyStmt = $conn->prepare("
                INSERT INTO connection_history (connection_type, source_type, source_id, source_port, target_type, target_id, target_port, action, old_values)
                VALUES (?, ?, ?, ?, 'switch', ?, ?, 'deleted', ?)
            ");
            
            $connectionType = $panelType === 'patch' ? 'switch_to_patch' : 'switch_to_fiber';
            $oldValues = json_encode($panelPort, JSON_UNESCAPED_UNICODE);
            
            $historyStmt->bind_param("ssiiiis", 
                $connectionType, $panelType, $panelId, $portNumber,
                $connectedSwitchId, $connectedSwitchPort, $oldValues
            );
            $historyStmt->execute();
            $historyStmt->close();
        }
        
        $conn->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Bağlantı başarıyla kesildi',
            'data' => [
                'panel_id' => $panelId,
                'panel_type' => $panelType,
                'port_number' => $portNumber,
                'disconnected_switch_id' => $connectedSwitchId,
                'disconnected_switch_port' => $connectedSwitchPort
            ]
        ]);
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
    
} catch (Exception $e) {
    error_log("Disconnect panel port error: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}

$conn->close();
?>