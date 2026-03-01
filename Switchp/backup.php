<?php
include "db.php";

header('Content-Type: application/json');

try {
    $action = $_REQUEST['action'] ?? '';
    $backupName = $_REQUEST['name'] ?? '';
    
    if ($action === 'create') {
        // Tüm verileri al
        $racksResult = $conn->query("SELECT * FROM racks");
        $switchesResult = $conn->query("SELECT * FROM switches");
        $portsResult = $conn->query("SELECT * FROM ports");
        
        $backupData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'name' => $backupName ?: 'Yedek_' . date('Ymd_His'),
            'data' => [
                'racks' => $racksResult->fetch_all(MYSQLI_ASSOC),
                'switches' => $switchesResult->fetch_all(MYSQLI_ASSOC),
                'ports' => $portsResult->fetch_all(MYSQLI_ASSOC)
            ]
        ];
        
        // Yedek dosyasını kaydet
        $backupDir = 'backups/';
        if (!file_exists($backupDir)) {
            mkdir($backupDir, 0777, true);
        }
        
        $filename = $backupDir . $backupData['name'] . '.json';
        file_put_contents($filename, json_encode($backupData, JSON_PRETTY_PRINT));
        
        echo json_encode([
            'success' => true,
            'status' => 'ok',
            'message' => 'Yedek başarıyla oluşturuldu: ' . basename($filename),
            'filename' => $filename
        ]);
        
    } elseif ($action === 'list') {
        $backupDir = 'backups/';
        $backups = [];
        
        if (file_exists($backupDir)) {
            $files = glob($backupDir . '*.json');
            foreach ($files as $file) {
                $content = json_decode(file_get_contents($file), true);
                $backups[] = [
                    'name' => $content['name'],
                    'timestamp' => $content['timestamp'],
                    'file' => basename($file),
                    'size' => filesize($file)
                ];
            }
        }
        
        echo json_encode([
            'success' => true,
            'status' => 'ok',
            'backups' => $backups
        ]);
        
    } elseif ($action === 'restore') {
        $filename = isset($_REQUEST['file']) ? 'backups/' . basename($_REQUEST['file']) : '';
        
        // Ensure file is within the backups directory
        $backupDir = realpath('backups');
        $resolvedFile = $filename ? realpath($filename) : false;
        if (!$resolvedFile || !$backupDir || strpos($resolvedFile, $backupDir . DIRECTORY_SEPARATOR) !== 0) {
            throw new Exception('Geçersiz yedek dosyası');
        }
        
        $backupData = json_decode(file_get_contents($filename), true);
        
        // Veritabanını temizle
        $conn->query("SET FOREIGN_KEY_CHECKS = 0");
        $conn->query("TRUNCATE TABLE ports");
        $conn->query("TRUNCATE TABLE switches");
        $conn->query("TRUNCATE TABLE racks");
        $conn->query("SET FOREIGN_KEY_CHECKS = 1");
        
        // Rack'leri geri yükle
        foreach ($backupData['data']['racks'] as $rack) {
            $stmt = $conn->prepare("INSERT INTO racks (id, name, location, description, slots) VALUES (?,?,?,?,?)");
            $stmt->bind_param("isssi", $rack['id'], $rack['name'], $rack['location'], $rack['description'], $rack['slots']);
            $stmt->execute();
        }
        
        // Switch'leri geri yükle
        foreach ($backupData['data']['switches'] as $switch) {
            $stmt = $conn->prepare("INSERT INTO switches (id, name, brand, model, ports, status, rack_id, ip) VALUES (?,?,?,?,?,?,?,?)");
            $stmt->bind_param("isssisii", $switch['id'], $switch['name'], $switch['brand'], $switch['model'], $switch['ports'], $switch['status'], $switch['rack_id'], $switch['ip']);
            $stmt->execute();
        }
        
        // Portları geri yükle
        foreach ($backupData['data']['ports'] as $port) {
            $stmt = $conn->prepare("INSERT INTO ports (id, switch_id, port_no, type, device, ip, mac, rack_port) VALUES (?,?,?,?,?,?,?,?)");
            $stmt->bind_param("iiissssi", $port['id'], $port['switch_id'], $port['port_no'], $port['type'], $port['device'], $port['ip'], $port['mac'], $port['rack_port']);
            $stmt->execute();
        }
        
        echo json_encode([
            'success' => true,
            'status' => 'ok',
            'message' => 'Yedek başarıyla geri yüklendi'
        ]);
        
    } else {
        throw new Exception('Geçersiz işlem');
    }
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'status' => 'error',
        'error' => $e->getMessage(),
        'message' => $e->getMessage()
    ]);
}

$conn->close();
?>