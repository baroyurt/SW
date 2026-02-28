<?php
// updatePort.php - GÜNCEL VERSİYON (CONNECTED_TO DESTEKLİ)
include "db.php";

header('Content-Type: application/json; charset=utf-8');

// Hata raporlama (log'a yaz)
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/port_update_errors.log');

try {
    $input = file_get_contents("php://input");
    $data = json_decode($input, true);
    
    if (!$data || !isset($data['switchId'])) {
        throw new Exception("Eksik veri: switchId gerekli");
    }
    
    $switchId = intval($data['switchId']);
    $portNo = isset($data['port']) ? intval($data['port']) : 0;
    
    // ==============================
    // PANEL BAĞLANTI BİLGİLERİ (YENİ EKLENDİ)
    // ==============================
    $connected_panel_id = isset($data['connected_panel_id']) ? (int)$data['connected_panel_id'] : null;
    $connected_panel_port = isset($data['connected_panel_port']) ? (int)$data['connected_panel_port'] : null;
    $connected_to = isset($data['connected_to']) ? trim($data['connected_to']) : null;
    
    // ==============================
    // TÜM PORTLARI BOŞA ÇEKME
    // ==============================
    if (isset($data['action']) && $data['action'] === 'reset_all') {
        $resetStmt = $conn->prepare("
            UPDATE ports 
            SET type = 'BOŞ', 
                device = '', 
                ip = '', 
                mac = '', 
                rack_port = 0,
                is_hub = 0,
                hub_name = NULL,
                multiple_connections = NULL,
                connection_info = NULL,
                device_count = 0,
                connected_panel_id = NULL,
                connected_panel_port = NULL,
                connection_info_preserved = '',
                connected_to = NULL,
                updated_at = NOW()
            WHERE switch_id = ?
        ");
        
        $resetStmt->bind_param("i", $switchId);
        
        if ($resetStmt->execute()) {
            $affectedRows = $resetStmt->affected_rows;
            $resetStmt->close();
            
            echo json_encode([
                "status" => "ok",
                "message" => "Tüm portlar boşa çekildi ($affectedRows port temizlendi)"
            ]);
        } else {
            throw new Exception("Port sıfırlama hatası: " . $resetStmt->error);
        }
        
        $conn->close();
        return;
    }
    
    // ==============================
    // HUB PORT İŞLEMLERİ
    // ==============================
    if (isset($data['isHub']) && $data['isHub']) {
        $isHub = 1;
        $hubName = isset($data['hubName']) ? trim($data['hubName']) : '';
        $connections = isset($data['connections']) ? $data['connections'] : [];
        
        if (empty($hubName)) {
            throw new Exception("Hub adı boş olamaz");
        }
        
        // Port kontrolü (PANEL BAĞLANTILARI KORUNACAK)
        $checkStmt = $conn->prepare("SELECT id, is_hub, connected_panel_id, connected_panel_port, connected_to FROM ports WHERE switch_id = ? AND port_no = ?");
        $checkStmt->bind_param("ii", $switchId, $portNo);
        $checkStmt->execute();
        $checkResult = $checkStmt->get_result();
        $portData = $checkResult->fetch_assoc();
        $checkStmt->close();
        
        // prepare connection aggregation
        $multipleConnectionsJson = null;
        $deviceCount = 0;
        if (!empty($connections)) {
            // Connections can be array or JSON string
            if (is_string($connections)) {
                $decoded = json_decode($connections, true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    $connectionsArr = $decoded;
                } else {
                    $connectionsArr = [];
                }
            } else {
                $connectionsArr = $connections;
            }
            $deviceCount = count($connectionsArr);
            $multipleConnectionsJson = json_encode($connectionsArr, JSON_UNESCAPED_UNICODE);
        }
        
        // build combined ip/mac/device for storage (for hub summary)
        $combinedDevice = $hubName;
        $combinedIp = '';
        $combinedMac = '';
        if (!empty($connectionsArr) && is_array($connectionsArr)) {
            $ips = [];
            $macs = [];
            $devs = [];
            foreach ($connectionsArr as $c) {
                if (!empty($c['ip'])) $ips[] = $c['ip'];
                if (!empty($c['mac'])) $macs[] = $c['mac'];
                if (!empty($c['device'])) $devs[] = $c['device'];
            }
            $combinedIp = implode(", ", array_unique($ips));
            $combinedMac = implode(", ", array_unique($macs));
            if (empty($combinedDevice)) $combinedDevice = !empty($devs) ? implode(", ", array_slice($devs,0,3)) : 'Hub Port';
        }
        
        if ($checkResult->num_rows > 0) {
            // Güncelle - PANEL BAĞLANTILARI KORU
            $updateStmt = $conn->prepare("
                UPDATE ports 
                SET type = 'HUB', 
                    device = ?, 
                    ip = ?, 
                    mac = ?, 
                    is_hub = ?, 
                    hub_name = ?, 
                    multiple_connections = ?,
                    connection_info = ?,
                    device_count = ?,
                    updated_at = NOW()
                WHERE switch_id = ? AND port_no = ?
            ");
            
            $connectionInfo = isset($data['connectionInfo']) ? $data['connectionInfo'] : '';
            $updateStmt->bind_param("ssssisssiii", 
                $combinedDevice, 
                $combinedIp, 
                $combinedMac, 
                $isHub, 
                $hubName, 
                $multipleConnectionsJson, 
                $connectionInfo,
                $deviceCount,
                $switchId, 
                $portNo
            );
            
            if (!$updateStmt->execute()) {
                throw new Exception("Hub port güncelleme hatası: " . $updateStmt->error);
            }
            $updateStmt->close();
            
            echo json_encode([
                "status" => "ok",
                "message" => "Hub portu güncellendi",
                "hubInfo" => [
                    "name" => $hubName,
                    "deviceCount" => $deviceCount,
                    "port" => $portNo,
                    "panelConnected" => !empty($portData['connected_panel_id'])
                ]
            ]);
        } else {
            // Yeni ekle
            $insertStmt = $conn->prepare("
                INSERT INTO ports (switch_id, port_no, type, device, ip, mac, 
                                  is_hub, hub_name, multiple_connections, connection_info, device_count,
                                  connected_panel_id, connected_panel_port, connected_to)
                VALUES (?, ?, 'HUB', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            // connected panel fields - preserve if provided
            $cpid = $connected_panel_id !== null ? $connected_panel_id : null;
            $cpp = $connected_panel_port !== null ? $connected_panel_port : null;
            $ct = $connected_to !== null ? $connected_to : null;
            
            $insertStmt->bind_param("iisssisssiiis", 
                $switchId, 
                $portNo, 
                $combinedDevice, 
                $combinedIp, 
                $combinedMac, 
                $isHub, 
                $hubName, 
                $multipleConnectionsJson,
                $connectionInfo,
                $deviceCount,
                $cpid,
                $cpp,
                $ct
            );
            
            if (!$insertStmt->execute()) {
                throw new Exception("Hub port ekleme hatası: " . $insertStmt->error);
            }
            $insertStmt->close();
            
            echo json_encode([
                "status" => "ok",
                "message" => "Hub portu eklendi",
                "hubInfo" => [
                    "name" => $hubName,
                    "deviceCount" => $deviceCount,
                    "port" => $portNo
                ]
            ]);
        }
        
        $conn->close();
        return;
    }
    
    // ==============================
    // NORMAL PORT GÜNCELLME
    // ==============================
    if ($portNo <= 0) {
        throw new Exception("Geçersiz port numarası");
    }
    
    $type = isset($data['type']) ? trim($data['type']) : '';
    $device = isset($data['device']) ? trim($data['device']) : '';
    $ip = isset($data['ip']) ? trim($data['ip']) : '';
    $mac = isset($data['mac']) ? trim($data['mac']) : '';
    $rackPort = isset($data['rackPort']) ? intval($data['rackPort']) : 0;
    $patchPanel = isset($data['patchPanel']) ? trim($data['patchPanel']) : '';
    $isHub = isset($data['isHub']) && $data['isHub'] ? 1 : 0;
    $hubName = isset($data['hubName']) ? trim($data['hubName']) : '';
    $multipleConnections = isset($data['connections']) ? (is_array($data['connections']) ? json_encode($data['connections'], JSON_UNESCAPED_UNICODE) : $data['connections']) : null;
    $connectionInfo = isset($data['connectionInfo']) ? $data['connectionInfo'] : null;
    $deviceCount = isset($data['deviceCount']) ? intval($data['deviceCount']) : 0;
    
    // Port var mı kontrol et
    $checkStmt = $conn->prepare("SELECT id, is_hub, connected_panel_id, connected_panel_port, connected_to FROM ports WHERE switch_id = ? AND port_no = ?");
    $checkStmt->bind_param("ii", $switchId, $portNo);
    $checkStmt->execute();
    $checkResult = $checkStmt->get_result();
    $portData = $checkResult->fetch_assoc();
    $checkStmt->close();
    
    // Track old description for alarm detection
    $oldDescription = $portData ? ($portData['connected_to'] ?? '') : '';
    
    if ($checkResult->num_rows > 0) {
        // Eğer bu port daha önce hub'sa ve şimdi normal port yapılıyorsa
        if ($portData['is_hub'] == 1 && $isHub == 0) {
            // Hub kolonlarını temizle, PANEL BAĞLANTILARI KORU
            $hubName = '';
            $multipleConnections = null;
            $connectionInfo = null;
            $deviceCount = 0;
            
            // Panel bağlantılarını koru
            $connected_panel_id = $portData['connected_panel_id'];
            $connected_panel_port = $portData['connected_panel_port'];
            $connected_to = $portData['connected_to'];
        } else {
            // Panel bağlantılarını koru (eğer yeni değer gelmemişse)
            if ($connected_panel_id === null && isset($portData['connected_panel_id'])) {
                $connected_panel_id = $portData['connected_panel_id'];
            }
            if ($connected_panel_port === null && isset($portData['connected_panel_port'])) {
                $connected_panel_port = $portData['connected_panel_port'];
            }
            if (empty($connected_to) && !empty($portData['connected_to'])) {
                $connected_to = $portData['connected_to'];
            }
        }
        
        // Güncelle - connected_to dahil
        $updateStmt = $conn->prepare("
            UPDATE ports 
            SET type = ?, 
                device = ?, 
                ip = ?, 
                mac = ?, 
                rack_port = ?,
                is_hub = ?, 
                hub_name = ?, 
                multiple_connections = ?,
                connection_info = ?,
                device_count = ?,
                connected_panel_id = ?,
                connected_panel_port = ?,
                connection_info_preserved = ?,
                connected_to = ?,
                updated_at = NOW()
            WHERE switch_id = ? AND port_no = ?
        ");
        
        $connectionInfoPreserved = $connectionInfo !== null ? $connectionInfo : ($portData['connected_to'] ?? '');
        
        $cpid = $connected_panel_id !== null ? $connected_panel_id : null;
        $cpp = $connected_panel_port !== null ? $connected_panel_port : null;
        $ctp = $connected_to !== null ? $connected_to : null;
        
        $updateStmt->bind_param("ssssissssiiissii", 
            $type, 
            $device, 
            $ip, 
            $mac, 
            $rackPort,
            $isHub, 
            $hubName, 
            $multipleConnections,
            $connectionInfo,
            $deviceCount,
            $cpid,
            $cpp,
            $connectionInfoPreserved,
            $ctp,
            $switchId, 
            $portNo
        );
        
        if ($updateStmt->execute()) {
            $affectedRows = $updateStmt->affected_rows;
            $updateStmt->close();
            
            // Check if description (connected_to) changed and create alarm
            $newDescription = $ctp ?? '';
            if ($oldDescription !== $newDescription && ($oldDescription !== '' || $newDescription !== '')) {
                // Description changed - create alarm
                try {
                    $alarmData = [
                        'action' => 'create_description_alarm',
                        'switchId' => $switchId,
                        'portNo' => $portNo,
                        'oldDescription' => $oldDescription,
                        'newDescription' => $newDescription
                    ];
                    
                    // Call alarm API
                    $ch = curl_init('http://localhost' . dirname($_SERVER['PHP_SELF']) . '/port_change_api.php');
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_POST, true);
                    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($alarmData));
                    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                    
                    $alarmResponse = curl_exec($ch);
                    $alarmResult = json_decode($alarmResponse, true);
                    curl_close($ch);
                    
                    if ($alarmResult && isset($alarmResult['success']) && $alarmResult['success']) {
                        error_log("Port description alarm created: Switch $switchId, Port $portNo");
                    } else {
                        error_log("Failed to create port description alarm: " . ($alarmResult['message'] ?? 'Unknown error'));
                    }
                } catch (Exception $e) {
                    // Alarm creation failed, but port update succeeded - just log
                    error_log("Error creating description change alarm: " . $e->getMessage());
                }
            }
            
            $panelInfo = '';
            if ($cpid) {
                $panelInfo = " (Panel: {$cpid}:{$cpp})";
            }
            
            echo json_encode([
                "status" => "ok",
                "message" => "Port güncellendi ({$type}){$panelInfo}",
                "portInfo" => [
                    "port" => $portNo,
                    "type" => $type,
                    "device" => $device,
                    "ip" => $ip,
                    "mac" => $mac,
                    "isHub" => $isHub == 1,
                    "hasConnections" => !empty($multipleConnections),
                    "panelConnected" => $cpid ? true : false,
                    "connected_to" => $ctp
                ]
            ]);
        } else {
            throw new Exception("Port güncelleme hatası: " . $updateStmt->error);
        }
        
    } else {
        // Yeni port ekle - connected_to dahil
        $insertStmt = $conn->prepare("
            INSERT INTO ports (switch_id, port_no, type, device, ip, mac, rack_port, 
                              is_hub, hub_name, multiple_connections, connection_info, device_count,
                              connected_panel_id, connected_panel_port, connection_info_preserved, connected_to)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $cpid = $connected_panel_id !== null ? $connected_panel_id : null;
        $cpp = $connected_panel_port !== null ? $connected_panel_port : null;
        $ctp = $connected_to !== null ? $connected_to : null;
        
        $insertStmt->bind_param("iissssiisssiiiss", 
            $switchId, 
            $portNo, 
            $type, 
            $device, 
            $ip, 
            $mac, 
            $rackPort,
            $isHub, 
            $hubName, 
            $multipleConnections,
            $connectionInfo,
            $deviceCount,
            $cpid,
            $cpp,
            $connectionInfoPreserved,
            $ctp
        );
        
        if ($insertStmt->execute()) {
            $newPortId = $conn->insert_id;
            $insertStmt->close();
            
            echo json_encode([
                "status" => "ok",
                "message" => "Port eklendi ({$type})",
                "portInfo" => [
                    "id" => $newPortId,
                    "port" => $portNo,
                    "type" => $type,
                    "device" => $device,
                    "hasConnections" => !empty($multipleConnections),
                    "panelConnected" => $cpid ? true : false
                ]
            ]);
        } else {
            throw new Exception("Port ekleme hatası: " . $insertStmt->error);
        }
    }
    
} catch (Exception $e) {
    error_log("Port update error: " . $e->getMessage() . " | Data: " . json_encode($data));
    
    echo json_encode([
        "status" => "error",
        "message" => $e->getMessage()
    ]);
}

$conn->close();
?>