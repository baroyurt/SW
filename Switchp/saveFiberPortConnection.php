<?php
// saveFiberPortConnection.php
// Accepts JSON payload to create/update fiber port connections:
// {
//   "side_a": { "type":"fiber_port", "panel_id":10, "port":1 } OR { "type":"switch", "id":31, "port":49 },
//   "side_b": { ... },
//   "user": "admin" (optional)
// }

include "db.php";

header('Content-Type: application/json; charset=utf-8');

function err($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(['success' => false, 'message' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

function ok($msg, $data = []) {
    echo json_encode(array_merge(['success' => true, 'message' => $msg], $data), JSON_UNESCAPED_UNICODE);
    exit;
}

function fetchFiberPortForUpdate($conn, $panelId, $portNumber) {
    $stmt = $conn->prepare("SELECT * FROM fiber_ports WHERE panel_id = ? AND port_number = ? FOR UPDATE");
    $stmt->bind_param("ii", $panelId, $portNumber);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_assoc();
    $stmt->close();
    return $row;
}

function createFiberPort($conn, $panelId, $portNumber) {
    $stmt = $conn->prepare("INSERT INTO fiber_ports (panel_id, port_number, status, created_at) VALUES (?, ?, 'inactive', NOW())");
    $stmt->bind_param("ii", $panelId, $portNumber);
    if (!$stmt->execute()) {
        $stmt->close();
        throw new Exception("Failed to create fiber_ports row: " . $conn->error);
    }
    $stmt->close();
    // return newly created row (locked)
    return fetchFiberPortForUpdate($conn, $panelId, $portNumber);
}

function fetchSwitchForUpdate($conn, $switchId) {
    $stmt = $conn->prepare("SELECT * FROM switches WHERE id = ? FOR UPDATE");
    $stmt->bind_param("i", $switchId);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_assoc();
    $stmt->close();
    return $row;
}

/**
 * Write to connection_history safely.
 * Bind everything as string to avoid type-definition mismatches.
 */
function writeHistory($conn, $user, $connectionType, $srcType, $srcId, $srcPort, $tgtType, $tgtId, $tgtPort, $action, $oldValues = null, $newValues = null) {
    $stmt = $conn->prepare("
        INSERT INTO connection_history
        (user_name, connection_type, source_type, source_id, source_port, target_type, target_id, target_port, action, old_values, new_values)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");
    if (!$stmt) {
        throw new Exception("History prepare failed: " . $conn->error);
    }
    $oldJson = $oldValues ? json_encode($oldValues, JSON_UNESCAPED_UNICODE) : null;
    $newJson = $newValues ? json_encode($newValues, JSON_UNESCAPED_UNICODE) : null;
    // force everything to strings to avoid mismatch
    $s_srcId = (string)$srcId;
    $s_srcPort = (string)$srcPort;
    $s_tgtId = (string)$tgtId;
    $s_tgtPort = (string)$tgtPort;
    $user_s = (string)$user;
    $connectionType_s = (string)$connectionType;
    $srcType_s = (string)$srcType;
    $tgtType_s = (string)$tgtType;
    $action_s = (string)$action;
    $oldJson_s = (string)$oldJson;
    $newJson_s = (string)$newJson;
    $stmt->bind_param("sssssssssss",
        $user_s,
        $connectionType_s,
        $srcType_s,
        $s_srcId,
        $s_srcPort,
        $tgtType_s,
        $s_tgtId,
        $s_tgtPort,
        $action_s,
        $oldJson_s,
        $newJson_s
    );
    if (!$stmt->execute()) {
        $stmt->close();
        throw new Exception("Failed to write history: " . $conn->error);
    }
    $stmt->close();
}

// read input
$raw = file_get_contents("php://input");
$payload = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE) err("Invalid JSON: " . json_last_error_msg());

if (!isset($payload['side_a']) || !isset($payload['side_b'])) err("side_a and side_b required");

$user = isset($payload['user']) ? trim($payload['user']) : (defined('CURRENT_USER') ? CURRENT_USER : 'system');

$sideA = $payload['side_a'];
$sideB = $payload['side_b'];

$validSideType = function($s) {
    return isset($s['type']) && in_array($s['type'], ['fiber_port', 'switch']);
};

if (!$validSideType($sideA) || !$validSideType($sideB)) err("side types must be 'fiber_port' or 'switch'");

// at least one side must be fiber_port
if ($sideA['type'] !== 'fiber_port' && $sideB['type'] !== 'fiber_port') {
    err("At least one side must be a fiber_port");
}

try {
    $conn->begin_transaction();

    // normalize sides so that A is fiber_port if any
    if ($sideA['type'] !== 'fiber_port' && $sideB['type'] === 'fiber_port') {
        $tmp = $sideA; $sideA = $sideB; $sideB = $tmp;
    }

    // Side A must be fiber_port
    if ($sideA['type'] !== 'fiber_port') throw new Exception("Unexpected side types normalization error");

    $aPanel = intval($sideA['panel_id'] ?? 0);
    $aPort  = intval($sideA['port'] ?? 0);
    if ($aPanel <= 0 || $aPort <= 0) throw new Exception("side_a must include panel_id and port");

    $aRow = fetchFiberPortForUpdate($conn, $aPanel, $aPort);
    if (!$aRow) {
        // create row if missing
        $aRow = createFiberPort($conn, $aPanel, $aPort);
    }

    $oldA = $aRow;

    if ($sideB['type'] === 'fiber_port') {
        $bPanel = intval($sideB['panel_id'] ?? 0);
        $bPort  = intval($sideB['port'] ?? 0);
        if ($bPanel <= 0 || $bPort <= 0) throw new Exception("side_b fiber_port must include panel_id and port");

        $bRow = fetchFiberPortForUpdate($conn, $bPanel, $bPort);
        if (!$bRow) {
            $bRow = createFiberPort($conn, $bPanel, $bPort);
        }
        $oldB = $bRow;

        // Clear previous counterpart of A if pointing elsewhere
        if (!empty($aRow['connected_fiber_panel_id']) && !empty($aRow['connected_fiber_panel_port'])) {
            $prevPanel = intval($aRow['connected_fiber_panel_id']);
            $prevPort  = intval($aRow['connected_fiber_panel_port']);
            if (!($prevPanel === $bPanel && $prevPort === $bPort)) {
                $stmt = $conn->prepare("SELECT * FROM fiber_ports WHERE panel_id = ? AND port_number = ? FOR UPDATE");
                $stmt->bind_param("ii", $prevPanel, $prevPort);
                $stmt->execute();
                $prevRow = $stmt->get_result()->fetch_assoc();
                $stmt->close();
                if ($prevRow) {
                    if (intval($prevRow['connected_fiber_panel_id']) === $aPanel && intval($prevRow['connected_fiber_panel_port']) === $aPort) {
                        $prevId = $prevRow['id'];
                        $u = $conn->prepare("UPDATE fiber_ports SET connected_fiber_panel_id = NULL, connected_fiber_panel_port = NULL, connection_type = 'inactive', status = 'inactive', connection_details = NULL, updated_at = NOW(), sync_version = sync_version + 1 WHERE id = ?");
                        $u->bind_param("i", $prevId);
                        if (!$u->execute()) { $u->close(); throw new Exception("Failed clearing previous counterpart: " . $conn->error); }
                        $u->close();
                        writeHistory($conn, $user, 'fiber_to_fiber', 'fiber_panel', $prevRow['panel_id'], $prevRow['port_number'], 'fiber_panel', $aPanel, $aPort, 'deleted', $prevRow, null);
                    }
                }
            }
        }
        // Clear previous counterpart of B if pointing elsewhere
        if (!empty($bRow['connected_fiber_panel_id']) && !empty($bRow['connected_fiber_panel_port'])) {
            $prevPanel = intval($bRow['connected_fiber_panel_id']);
            $prevPort  = intval($bRow['connected_fiber_panel_port']);
            if (!($prevPanel === $aPanel && $prevPort === $aPort)) {
                $stmt = $conn->prepare("SELECT * FROM fiber_ports WHERE panel_id = ? AND port_number = ? FOR UPDATE");
                $stmt->bind_param("ii", $prevPanel, $prevPort);
                $stmt->execute();
                $prevRow = $stmt->get_result()->fetch_assoc();
                $stmt->close();
                if ($prevRow) {
                    if (intval($prevRow['connected_fiber_panel_id']) === $bPanel && intval($prevRow['connected_fiber_panel_port']) === $bPort) {
                        $prevId = $prevRow['id'];
                        $u = $conn->prepare("UPDATE fiber_ports SET connected_fiber_panel_id = NULL, connected_fiber_panel_port = NULL, connection_type = 'inactive', status = 'inactive', connection_details = NULL, updated_at = NOW(), sync_version = sync_version + 1 WHERE id = ?");
                        $u->bind_param("i", $prevId);
                        if (!$u->execute()) { $u->close(); throw new Exception("Failed clearing previous B counterpart: " . $conn->error); }
                        $u->close();
                        writeHistory($conn, $user, 'fiber_to_fiber', 'fiber_panel', $prevRow['panel_id'], $prevRow['port_number'], 'fiber_panel', $bPanel, $bPort, 'deleted', $prevRow, null);
                    }
                }
            }
        }

        // Set A <-> B
        $aRowId = $aRow['id'];
        $bRowId = $bRow['id'];

        $uA = $conn->prepare("UPDATE fiber_ports SET connected_fiber_panel_id = ?, connected_fiber_panel_port = ?, connection_type = 'panel_to_panel', status = 'active', connection_details = ?, updated_at = NOW(), sync_version = sync_version + 1 WHERE id = ?");
        $details = json_encode([
            'type' => 'panel_to_panel',
            'peer_panel' => $bPanel,
            'peer_port' => $bPort,
            'user' => $user,
            'time' => date('c')
        ], JSON_UNESCAPED_UNICODE);
        $uA->bind_param("iisi", $bPanel, $bPort, $details, $aRowId);
        if (!$uA->execute()) { $uA->close(); throw new Exception("Failed updating A fiber_ports: " . $conn->error); }
        $uA->close();

        $uB = $conn->prepare("UPDATE fiber_ports SET connected_fiber_panel_id = ?, connected_fiber_panel_port = ?, connection_type = 'panel_to_panel', status = 'active', connection_details = ?, updated_at = NOW(), sync_version = sync_version + 1 WHERE id = ?");
        $detailsB = json_encode([
            'type' => 'panel_to_panel',
            'peer_panel' => $aPanel,
            'peer_port' => $aPort,
            'user' => $user,
            'time' => date('c')
        ], JSON_UNESCAPED_UNICODE);
        $uB->bind_param("iisi", $aPanel, $aPort, $detailsB, $bRowId);
        if (!$uB->execute()) { $uB->close(); throw new Exception("Failed updating B fiber_ports: " . $conn->error); }
        $uB->close();

        // Write history
        writeHistory($conn, $user, 'fiber_to_fiber', 'fiber_panel', $aPanel, $aPort, 'fiber_panel', $bPanel, $bPort, 'created', $oldA, ['connected_fiber_panel_id'=>$bPanel,'connected_fiber_panel_port'=>$bPort]);
        writeHistory($conn, $user, 'fiber_to_fiber', 'fiber_panel', $bPanel, $bPort, 'fiber_panel', $aPanel, $aPort, 'created', $oldB, ['connected_fiber_panel_id'=>$aPanel,'connected_fiber_panel_port'=>$aPort]);

        $conn->commit();
        ok("Panel-to-panel fiber connection created", ['a' => ['panel'=>$aPanel,'port'=>$aPort],'b'=>['panel'=>$bPanel,'port'=>$bPort]]);

    } else { // sideB is switch
        $switchId = intval($sideB['id'] ?? 0);
        $switchPort = intval($sideB['port'] ?? 0);
        if ($switchId <= 0 || $switchPort <= 0) throw new Exception("side_b switch must include id and port");

        // lock switch row
        $sw = fetchSwitchForUpdate($conn, $switchId);
        if (!$sw) throw new Exception("Switch not found: " . $switchId);

        // clear any previous fiber_ports that claim this switch:port (except our A)
        $stmt = $conn->prepare("SELECT * FROM fiber_ports WHERE connected_switch_id = ? AND connected_switch_port = ? FOR UPDATE");
        $stmt->bind_param("ii", $switchId, $switchPort);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($r = $res->fetch_assoc()) {
            if (!(intval($r['panel_id']) === $aPanel && intval($r['port_number']) === $aPort)) {
                $rid = $r['id'];
                $u2 = $conn->prepare("UPDATE fiber_ports SET connected_switch_id = NULL, connected_switch_port = NULL, connection_type = 'inactive', status = 'inactive', connection_details = NULL, updated_at = NOW(), sync_version = sync_version + 1 WHERE id = ?");
                $u2->bind_param("i", $rid);
                if (!$u2->execute()) { $u2->close(); throw new Exception("Failed clearing other fiber_ports row: " . $conn->error); }
                $u2->close();
                writeHistory($conn, $user, 'fiber_to_switch', 'fiber_panel', $r['panel_id'], $r['port_number'], 'switch', $switchId, $switchPort, 'deleted', $r, null);
            }
        }
        $stmt->close();

        // set A -> switch
        $aRowId = $aRow['id'];
        $connDetails = json_encode(['type'=>'switch_fiber','switch_id'=>$switchId,'switch_port'=>$switchPort,'user'=>$user,'time'=>date('c')], JSON_UNESCAPED_UNICODE);
        $uA = $conn->prepare("UPDATE fiber_ports SET connected_switch_id = ?, connected_switch_port = ?, connection_type = 'switch_fiber', status = 'active', connection_details = ?, updated_at = NOW(), sync_version = sync_version + 1 WHERE id = ?");
        $uA->bind_param("iisi", $switchId, $switchPort, $connDetails, $aRowId);
        if (!$uA->execute()) { $uA->close(); throw new Exception("Failed updating fiber_ports (A) to switch: " . $conn->error); }
        $uA->close();

        // update or insert ports table record for switch side (reflect connected fiber panel)
        // NOTE: For fiber panels, we store info in connection_info_preserved but NOT in connected_panel_id
        // because connected_panel_id has FK to patch_panels, not fiber_panels
        $connInfoPreserved = $sw['name'] . "-FiberPort-" . $switchPort . " ← Fiber Panel " . $aPanel . " Port " . $aPort;
        $stmtPort = $conn->prepare("SELECT id FROM ports WHERE switch_id = ? AND port_no = ? FOR UPDATE");
        $stmtPort->bind_param("ii", $switchId, $switchPort);
        $stmtPort->execute();
        $pr = $stmtPort->get_result()->fetch_assoc();
        $stmtPort->close();
        if ($pr) {
            $prId = $pr['id'];
            // Update only connection_info_preserved, NOT connected_panel_id (that's for patch panels only)
            $upd = $conn->prepare("UPDATE ports SET connection_info_preserved = ?, updated_at = NOW() WHERE id = ?");
            $upd->bind_param("si", $connInfoPreserved, $prId);
            if (!$upd->execute()) {
                $upd->close();
                // fallback manual
                $q = "UPDATE ports SET connection_info_preserved = '" . $conn->real_escape_string($connInfoPreserved) . "', updated_at = NOW() WHERE id = " . intval($prId);
                if (!$conn->query($q)) throw new Exception("Failed to update ports row: " . $conn->error);
            } else {
                $upd->close();
            }
        } else {
            // insert minimal ports row if not exist (no connected_panel_id for fiber connections)
            $q = "INSERT INTO ports (switch_id, port_no, type, device, ip, mac, connection_info_preserved, created_at)
                  VALUES (" . intval($switchId) . ", " . intval($switchPort) . ", 'FIBER', '', '', '', '" . $conn->real_escape_string($connInfoPreserved) . "', NOW())";
            if (!$conn->query($q)) throw new Exception("Failed to insert ports row: " . $conn->error);
        }

        // history
        writeHistory($conn, $user, 'fiber_to_switch', 'fiber_panel', $aPanel, $aPort, 'switch', $switchId, $switchPort, 'created', $oldA, ['connected_switch_id'=>$switchId,'connected_switch_port'=>$switchPort]);

        $conn->commit();
        ok("Fiber panel connected to switch", ['panel' => ['id'=>$aPanel,'port'=>$aPort], 'switch'=>['id'=>$switchId,'port'=>$switchPort]]);
    }

} catch (Exception $e) {
    if ($conn->in_transaction) { @$conn->rollback(); }
    error_log("saveFiberPortConnection error: " . $e->getMessage() . " | payload: " . $raw);
    err("Operation failed: " . $e->getMessage(), 500);
}
?>