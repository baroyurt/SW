<?php
// saveRack.php - Rack ekleme / güncelleme
include "db.php";

header('Content-Type: application/json; charset=utf-8');

function jsonResponse($success, $message = '', $data = []) {
    echo json_encode(array_merge([
        'success' => $success,
        'message' => $message
    ], $data), JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    $raw = file_get_contents("php://input");
    $data = json_decode($raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        jsonResponse(false, 'Geçersiz JSON: ' . json_last_error_msg());
    }
    if (!$data) jsonResponse(false, 'Boş veri gönderildi');

    // Delete action
    if (isset($data['action']) && $data['action'] === 'delete') {
        $delId = isset($data['id']) ? intval($data['id']) : 0;
        if ($delId <= 0) jsonResponse(false, 'Geçersiz rack ID');
        $stmt = $conn->prepare("DELETE FROM racks WHERE id = ?");
        $stmt->bind_param("i", $delId);
        if ($stmt->execute()) { $stmt->close(); jsonResponse(true, 'Rack silindi'); }
        else { $stmt->close(); jsonResponse(false, 'Rack silinemedi: ' . $conn->error); }
    }

    $id = isset($data['id']) && $data['id'] !== '' ? intval($data['id']) : null;
    $name = isset($data['name']) ? trim($data['name']) : '';
    $location = isset($data['location']) ? trim($data['location']) : '';
    $description = isset($data['description']) ? trim($data['description']) : '';
    $slots = isset($data['slots']) ? intval($data['slots']) : 42;

    // Basit validasyon
    if ($name === '') jsonResponse(false, 'Rack adı boş olamaz');
    if ($slots < 1 || $slots > 1000) jsonResponse(false, 'Slot sayısı geçersiz (1-1000 arası olmalıdır)');

    // Eğer güncelleme ise mevcut rack'i kontrol et
    if ($id) {
        $checkStmt = $conn->prepare("SELECT id, name FROM racks WHERE id = ? LIMIT 1");
        $checkStmt->bind_param("i", $id);
        $checkStmt->execute();
        $res = $checkStmt->get_result();
        $existingRack = $res->fetch_assoc();
        $checkStmt->close();

        if (!$existingRack) {
            jsonResponse(false, 'Güncellenecek rack bulunamadı');
        }

        // Rack içindeki en yüksek kullanılan slotu bul
        $maxUsed = 0;

        // Switch'ler
        $s = $conn->prepare("SELECT MAX(position_in_rack) AS m FROM switches WHERE rack_id = ?");
        $s->bind_param("i", $id);
        $s->execute();
        $mr = $s->get_result()->fetch_assoc();
        $s->close();
        if ($mr && intval($mr['m']) > $maxUsed) $maxUsed = intval($mr['m']);

        // Patch paneller
        $p = $conn->prepare("SELECT MAX(position_in_rack) AS m FROM patch_panels WHERE rack_id = ?");
        $p->bind_param("i", $id);
        $p->execute();
        $pr = $p->get_result()->fetch_assoc();
        $p->close();
        if ($pr && intval($pr['m']) > $maxUsed) $maxUsed = intval($pr['m']);

        // Fiber paneller
        $f = $conn->prepare("SELECT MAX(position_in_rack) AS m FROM fiber_panels WHERE rack_id = ?");
        $f->bind_param("i", $id);
        $f->execute();
        $fr = $f->get_result()->fetch_assoc();
        $f->close();
        if ($fr && intval($fr['m']) > $maxUsed) $maxUsed = intval($fr['m']);

        if ($slots < $maxUsed) {
            jsonResponse(false, "Seçtiğiniz slot sayısı ({$slots}) mevcut en büyük kullanılan slot ({$maxUsed}) değerinden küçük. Lütfen önce cihaz/panel pozisyonlarını taşıyın veya daha yüksek bir slot sayısı girin.");
        }

        // Name uniqueness (başka bir rack ile aynı isim)
        $u = $conn->prepare("SELECT id FROM racks WHERE name = ? AND id != ? LIMIT 1");
        $u->bind_param("si", $name, $id);
        $u->execute();
        $ur = $u->get_result();
        if ($ur && $ur->num_rows > 0) {
            $u->close();
            jsonResponse(false, "Bu isimde başka bir rack zaten var");
        }
        $u->close();

        // update
        $stmt = $conn->prepare("UPDATE racks SET name = ?, location = ?, description = ?, slots = ? WHERE id = ?");
        $stmt->bind_param("sssii", $name, $location, $description, $slots, $id);
        if ($stmt->execute()) {
            $stmt->close();
            jsonResponse(true, 'Rack başarıyla güncellendi', ['rackId' => $id]);
        } else {
            $stmt->close();
            jsonResponse(false, 'Rack güncelleme hatası: ' . $conn->error);
        }

    } else {
        // Yeni ekleme: isim benzersizliği kontrolü
        $u = $conn->prepare("SELECT id FROM racks WHERE name = ? LIMIT 1");
        $u->bind_param("s", $name);
        $u->execute();
        $ur = $u->get_result();
        if ($ur && $ur->num_rows > 0) {
            $u->close();
            jsonResponse(false, "Bu isimde bir rack zaten mevcut");
        }
        $u->close();

        $stmt = $conn->prepare("INSERT INTO racks (name, location, description, slots) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("sssi", $name, $location, $description, $slots);
        if ($stmt->execute()) {
            $newId = $conn->insert_id;
            $stmt->close();
            jsonResponse(true, 'Rack başarıyla eklendi', ['rackId' => $newId]);
        } else {
            $stmt->close();
            jsonResponse(false, 'Rack ekleme hatası: ' . $conn->error);
        }
    }

} catch (Exception $e) {
    error_log("saveRack.php error: " . $e->getMessage());
    jsonResponse(false, 'Sunucu hatası: ' . $e->getMessage());
}

$conn->close();
?>