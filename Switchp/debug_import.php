<?php
// debug_import.php
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', 'import_debug.log');

// Buffer'ı başlat
ob_start();

// JSON header
header('Content-Type: application/json; charset=utf-8');

// DB bağlantısı
$host = "localhost";
$user = "root";
$pass = "";
$db   = "switchdb";

try {
    $conn = new mysqli($host, $user, $pass, $db);
    
    if ($conn->connect_error) {
        throw new Exception("DB bağlantı hatası: " . $conn->connect_error);
    }
    
    $conn->set_charset("utf8mb4");
    
    // Test için basit bir veri
    $testData = [[
        'name' => 'TEST-IMPORT-' . time(),
        'brand' => 'Cisco',
        'model' => 'Test',
        'ports' => 4,
        'rack' => 'OTEL',
        'ip' => '192.168.1.100',
        'ports_data' => [
            ['port' => 1, 'type' => 'AP', 'device' => 'Test AP', 'ip' => '192.168.1.101']
        ]
    ]];
    
    $conn->begin_transaction();
    
    foreach ($testData as $row) {
        // Rack kontrolü
        $rackName = $row['rack'];
        $rackCheck = $conn->prepare("SELECT id FROM racks WHERE name = ?");
        $rackCheck->bind_param("s", $rackName);
        $rackCheck->execute();
        $rackResult = $rackCheck->get_result();
        
        if ($rackResult->num_rows > 0) {
            $rackId = $rackResult->fetch_assoc()['id'];
        } else {
            $insertRack = $conn->prepare("INSERT INTO racks (name, location) VALUES (?, ?)");
            $location = $rackName . " Rack";
            $insertRack->bind_param("ss", $rackName, $location);
            $insertRack->execute();
            $rackId = $conn->insert_id;
        }
        
        // Switch ekle
        $switchName = $row['name'];
        $insertSwitch = $conn->prepare("
            INSERT INTO switches (name, brand, model, ports, rack_id, ip, status)
            VALUES (?, ?, ?, ?, ?, ?, 'online')
        ");
        $insertSwitch->bind_param("sssiis", 
            $row['name'], 
            $row['brand'], 
            $row['model'], 
            $row['ports'], 
            $rackId, 
            $row['ip']
        );
        $insertSwitch->execute();
        $switchId = $conn->insert_id;
        
        // Port ekle
        foreach ($row['ports_data'] as $port) {
            $insertPort = $conn->prepare("
                INSERT INTO ports (switch_id, port_no, type, device, ip, mac, rack_port)
                VALUES (?, ?, ?, ?, ?, '', 0)
            ");
            $insertPort->bind_param("iisss", 
                $switchId, 
                $port['port'], 
                $port['type'], 
                $port['device'], 
                $port['ip']
            );
            $insertPort->execute();
        }
    }
    
    $conn->commit();
    
    // Buffer'ı temizle ve JSON döndür
    ob_end_clean();
    
    echo json_encode([
        'status' => 'ok',
        'message' => 'Debug import başarılı'
    ]);
    
} catch (Exception $e) {
    // Hata olursa buffer'ı temizle ve hata mesajını döndür
    if (ob_get_length()) ob_end_clean();
    
    echo json_encode([
        'status' => 'error',
        'message' => 'Hata: ' . $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);
}

if (isset($conn)) $conn->close();
?>