<?php
// saveFiberPanel.php - GÜNCELLENDİ (fiber_ports otomatik oluşturma)

// Hata raporlama
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', 'fiber_panel_errors.log');

// Output buffer başlat
ob_start();

// JSON header
header('Content-Type: application/json; charset=utf-8');

// Hata fonksiyonu
function jsonResponse($success, $message, $data = []) {
    if (ob_get_length()) ob_end_clean();
    echo json_encode(array_merge([
        'success' => $success,
        'message' => $message
    ], $data));
    exit;
}

// DB bağlantısı
try {
    $host = "localhost";
    $user = "root";
    $pass = "";
    $db   = "switchdb";
    
    $conn = new mysqli($host, $user, $pass, $db);
    
    if ($conn->connect_error) {
        jsonResponse(false, 'DB bağlantı hatası: ' . $conn->connect_error);
    }
    
    // Karakter setini açıkça ayarla
    if (!$conn->set_charset("utf8mb4")) {
        error_log("Karakter seti ayarlanamadı: " . $conn->error);
    }
    
} catch (Exception $e) {
    jsonResponse(false, 'DB bağlantı hatası: ' . $e->getMessage());
}

// Input al
$input = file_get_contents("php://input");

if (empty($input)) {
    jsonResponse(false, 'Boş veri gönderildi');
}

// JSON decode
$data = json_decode($input, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    jsonResponse(false, 'JSON çözümleme hatası: ' . json_last_error_msg());
}

try {
    $rackId = isset($data['rackId']) ? intval($data['rackId']) : 0;
    $panelLetter = isset($data['panelLetter']) ? strtoupper(trim($data['panelLetter'])) : '';
    $totalFibers = isset($data['totalFibers']) ? intval($data['totalFibers']) : 0;
    $positionInRack = isset($data['positionInRack']) ? intval($data['positionInRack']) : 0;
    $description = isset($data['description']) ? trim($data['description']) : '';
    
    // Validasyon
    if ($rackId <= 0) {
        jsonResponse(false, 'Geçerli bir rack seçmelisiniz');
    }
    
    if (empty($panelLetter)) {
        jsonResponse(false, 'Panel harfi seçmelisiniz');
    }
    
    if ($totalFibers <= 0) {
        jsonResponse(false, 'Geçerli fiber sayısı girin');
    }
    
    if ($positionInRack <= 0) {
        jsonResponse(false, 'Geçerli bir slot pozisyonu seçin');
    }
    
    // Aynı rack'ta aynı harfte fiber panel var mı kontrol et
    $checkStmt = $conn->prepare("SELECT id FROM fiber_panels WHERE rack_id = ? AND panel_letter = ?");
    if (!$checkStmt) {
        throw new Exception("Kontrol sorgusu hazırlama hatası: " . $conn->error);
    }
    
    $checkStmt->bind_param("is", $rackId, $panelLetter);
    $checkStmt->execute();
    $checkResult = $checkStmt->get_result();
    
    if ($checkResult->num_rows > 0) {
        jsonResponse(false, "Bu rack'te $panelLetter fiber paneli zaten mevcut");
    }
    $checkStmt->close();
    
    // Aynı pozisyonda başka bir şey var mı kontrol et - ayrı sorgulamalar
    $occupied = false;
    $occupiedType = '';
    $occupiedName = '';
    
    // 1. Switch'leri kontrol et
    $checkSwitchStmt = $conn->prepare("SELECT name FROM switches WHERE rack_id = ? AND position_in_rack = ?");
    if (!$checkSwitchStmt) {
        throw new Exception("Switch kontrol sorgusu hazırlama hatası: " . $conn->error);
    }
    $checkSwitchStmt->bind_param("ii", $rackId, $positionInRack);
    $checkSwitchStmt->execute();
    $switchResult = $checkSwitchStmt->get_result();
    if ($switchResult->num_rows > 0) {
        $occupied = true;
        $row = $switchResult->fetch_assoc();
        $occupiedType = 'switch';
        $occupiedName = $row['name'];
    }
    $checkSwitchStmt->close();
    
    // 2. Patch panelleri kontrol et
    if (!$occupied) {
        $checkPatchStmt = $conn->prepare("SELECT panel_letter FROM patch_panels WHERE rack_id = ? AND position_in_rack = ?");
        if (!$checkPatchStmt) {
            throw new Exception("Patch panel kontrol sorgusu hazırlama hatası: " . $conn->error);
        }
        $checkPatchStmt->bind_param("ii", $rackId, $positionInRack);
        $checkPatchStmt->execute();
        $patchResult = $checkPatchStmt->get_result();
        if ($patchResult->num_rows > 0) {
            $occupied = true;
            $row = $patchResult->fetch_assoc();
            $occupiedType = 'patch panel';
            $occupiedName = $row['panel_letter'];
        }
        $checkPatchStmt->close();
    }
    
    // 3. Fiber panelleri kontrol et
    if (!$occupied) {
        $checkFiberStmt = $conn->prepare("SELECT panel_letter FROM fiber_panels WHERE rack_id = ? AND position_in_rack = ?");
        if (!$checkFiberStmt) {
            throw new Exception("Fiber panel kontrol sorgusu hazırlama hatası: " . $conn->error);
        }
        $checkFiberStmt->bind_param("ii", $rackId, $positionInRack);
        $checkFiberStmt->execute();
        $fiberResult = $checkFiberStmt->get_result();
        if ($fiberResult->num_rows > 0) {
            $occupied = true;
            $row = $fiberResult->fetch_assoc();
            $occupiedType = 'fiber panel';
            $occupiedName = $row['panel_letter'];
        }
        $checkFiberStmt->close();
    }
    
    if ($occupied) {
        jsonResponse(false, "Slot {$positionInRack} zaten dolu ({$occupiedType}: {$occupiedName})");
    }
    
    // Fiber panel ekle (transaction)
    $conn->begin_transaction();
    
    $insertStmt = $conn->prepare("
        INSERT INTO fiber_panels (rack_id, panel_letter, total_fibers, description, position_in_rack)
        VALUES (?, ?, ?, ?, ?)
    ");
    
    if (!$insertStmt) {
        throw new Exception("Ekleme sorgusu hazırlama hatası: " . $conn->error);
    }
    
    $insertStmt->bind_param("isisi", $rackId, $panelLetter, $totalFibers, $description, $positionInRack);
    
    if ($insertStmt->execute()) {
        $panelId = $conn->insert_id;
        
        // fiber_ports satırlarını oluştur (varsayılan 'inactive' status)
        $portStmt = $conn->prepare("
            INSERT INTO fiber_ports (panel_id, port_number, status)
            VALUES (?, ?, 'inactive')
        ");
        if (!$portStmt) {
            throw new Exception("fiber_ports insert sorgusu hazırlama hatası: " . $conn->error);
        }
        for ($i = 1; $i <= $totalFibers; $i++) {
            $portStmt->bind_param("ii", $panelId, $i);
            if (!$portStmt->execute()) {
                throw new Exception("fiber_ports eklenemedi: " . $portStmt->error);
            }
        }
        $portStmt->close();
        
        $conn->commit();
        
        jsonResponse(true, "Fiber panel oluşturuldu: $panelLetter", [
            'panelId' => $panelId,
            'panelLetter' => $panelLetter,
            'totalFibers' => $totalFibers
        ]);
    } else {
        $conn->rollback();
        throw new Exception("Fiber panel ekleme hatası: " . $insertStmt->error);
    }
    
    $insertStmt->close();
    
} catch (Exception $e) {
    if (isset($conn) && $conn->in_transaction) $conn->rollback();
    jsonResponse(false, $e->getMessage());
}

$conn->close();
?>