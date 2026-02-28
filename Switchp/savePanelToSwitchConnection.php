<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

header('Content-Type: application/json; charset=utf-8');
include "db.php";

function jsonResponse($success, $message, $data = []) {
    echo json_encode(array_merge([
        'success' => $success,
        'message' => $message
    ], $data), JSON_UNESCAPED_UNICODE);
    exit;
}

try {

    $data = json_decode(file_get_contents("php://input"), true);
    if (!$data) jsonResponse(false, "Geçersiz veri");

    $panelId   = (int)($data['panelId'] ?? 0);
    $panelType = $data['panelType'] ?? '';
    $panelPort = (int)($data['panelPort'] ?? 0);
    $switchId  = (int)($data['switchId'] ?? 0);
    $switchPort= (int)($data['switchPort'] ?? 0);

    if ($panelId<=0 || $panelPort<=0 || $switchId<=0 || $switchPort<=0)
        jsonResponse(false,"Eksik bilgi");

    if (!in_array($panelType,['patch','fiber']))
        jsonResponse(false,"Geçersiz panel tipi");

    $conn->begin_transaction();

    // Switch portu al
    $stmt = $conn->prepare("SELECT * FROM ports WHERE switch_id=? AND port_no=?");
    $stmt->bind_param("ii",$switchId,$switchPort);
    $stmt->execute();
    $portData = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    $connectionText = "Panel {$panelId} Port {$panelPort}";

    // Switch portu yaz
    if ($portData) {
        $stmt = $conn->prepare("
            UPDATE ports SET
                connected_panel_id=?,
                connected_panel_port=?,
                connection_info_preserved=?
            WHERE switch_id=? AND port_no=?
        ");
        $stmt->bind_param("iisii",
            $panelId, $panelPort, $connectionText,
            $switchId, $switchPort
        );
        $stmt->execute();
        $stmt->close();
    } else {
        $stmt = $conn->prepare("
            INSERT INTO ports
            (switch_id,port_no,connected_panel_id,connected_panel_port,connection_info_preserved)
            VALUES (?,?,?,?,?)
        ");
        $stmt->bind_param("iiiis",
            $switchId,$switchPort,
            $panelId,$panelPort,$connectionText
        );
        $stmt->execute();
        $stmt->close();
    }

    $connectionDetails = json_encode([
        'switch_id'=>$switchId,
        'switch_port'=>$switchPort,
        'panel_id'=>$panelId,
        'panel_port'=>$panelPort,
        'time'=>date('Y-m-d H:i:s')
    ], JSON_UNESCAPED_UNICODE);

    if ($panelType === 'patch') {
        $stmt = $conn->prepare("
            INSERT INTO patch_ports
            (panel_id,port_number,status,connected_switch_id,connected_switch_port,connection_details)
            VALUES (?,?, 'active', ?,?,?)
            ON DUPLICATE KEY UPDATE
                status='active',
                connected_switch_id=VALUES(connected_switch_id),
                connected_switch_port=VALUES(connected_switch_port),
                connection_details=VALUES(connection_details)
        ");
    } else {
        $stmt = $conn->prepare("
            INSERT INTO fiber_ports
            (panel_id,port_number,status,connected_switch_id,connected_switch_port,connection_details)
            VALUES (?,?, 'active', ?,?,?)
            ON DUPLICATE KEY UPDATE
                status='active',
                connected_switch_id=VALUES(connected_switch_id),
                connected_switch_port=VALUES(connected_switch_port),
                connection_details=VALUES(connection_details)
        ");
    }

    $stmt->bind_param("iiiis",
        $panelId,$panelPort,
        $switchId,$switchPort,$connectionDetails
    );
    $stmt->execute();
    $stmt->close();

    $conn->commit();

    jsonResponse(true,"Bağlantı başarıyla kaydedildi");

} catch (Exception $e) {
    $conn->rollback();
    jsonResponse(false,$e->getMessage());
}

$conn->close();
?>