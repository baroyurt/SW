<?php
// disconnectFiberPort.php
// Disconnect a fiber port (panel port) or switch-side fiber connection.
// Accepts JSON:
// { "type":"fiber_port", "panel_id": 10, "port": 3, "user": "admin" }
// OR
// { "type":"switch", "switch_id": 31, "port": 49, "user": "admin" }

include "db.php";

header('Content-Type: application/json; charset=utf-8');

function jsonResponse($ok, $message, $data = []) {
    echo json_encode(array_merge([
        'success' => $ok,
        'message' => $message
    ], $data), JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    $raw = file_get_contents("php://input");
    $data = json_decode($raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Invalid JSON: " . json_last_error_msg());
    }
    if (!$data || !isset($data['type'])) {
        throw new Exception("Invalid request");
    }

    $user = isset($data['user']) ? trim($data['user']) : 'system';

    $type = $data['type'];

    $conn->begin_transaction();

    // Helper: insert history
    $insertHistory = function($conn, $connectionType, $srcType, $srcId, $srcPort, $tgtType, $tgtId, $tgtPort, $action, $oldValues, $newValues, $user) {
        $h = $conn->prepare("
            INSERT INTO connection_history
            (user_name, connection_type, source_type, source_id, source_port, target_type, target_id, target_port, action, old_values, new_values)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $oldJson = $oldValues ? json_encode($oldValues, JSON_UNESCAPED_UNICODE) : null;
        $newJson = $newValues ? json_encode($newValues, JSON_UNESCAPED_UNICODE) : null;
        $h->bind_param("ssii siissss", $user, $connectionType, $srcType, $srcId, $srcPort, $tgtType, $tgtId, $tgtPort, $action, $oldJson, $newJson);
        // Note: PHP's bind_param types must match count; use string placeholders for safety.
        // Because of portability differences, perform safer binding by converting ints to ints and strings to strings.
        // Simpler approach: use one prepared statement above but pass values as strings where required.
        // Execute:
        if (!$h->execute()) {
            $h->close();
            throw new Exception("Failed to write history: " . $conn->error);
        }
        $h->close();
    };

    if ($type === 'fiber_port') {
        $panelId = isset($data['panel_id']) ? intval($data['panel_id']) : 0;
        $portNo = isset($data['port']) ? intval($data['port']) : 0;
        if ($panelId <= 0 || $portNo <= 0) throw new Exception("Invalid panel_id or port");

        // Lock the port
        $stmt = $conn->prepare("SELECT * FROM fiber_ports WHERE panel_id = ? AND port_number = ? FOR UPDATE");
        $stmt->bind_param("ii", $panelId, $portNo);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if (!$row) throw new Exception("Fiber port not found");

        $oldValues = $row;

        // If connected to another fiber panel, clear counterpart (if points back)
        if (!empty($row['connected_fiber_panel_id']) && !empty($row['connected_fiber_panel_port'])) {
            $otherPanel = intval($row['connected_fiber_panel_id']);
            $otherPort = intval($row['connected_fiber_panel_port']);

            $s2 = $conn->prepare("SELECT * FROM fiber_ports WHERE panel_id = ? AND port_number = ? FOR UPDATE");
            $s2->bind_param("ii", $otherPanel, $otherPort);
            $s2->execute();
            $otherRow = $s2->get_result()->fetch_assoc();
            $s2->close();

            if ($otherRow) {
                // if counterpart points back to this port, clear it
                if (intval($otherRow['connected_fiber_panel_id']) === intval($panelId)
                    && intval($otherRow['connected_fiber_panel_port']) === intval($portNo)) {

                    $u = $conn->prepare("
                        UPDATE fiber_ports
                        SET connected_fiber_panel_id = NULL,
                            connected_fiber_panel_port = NULL,
                            connection_type = 'inactive',
                            connection_details = NULL,
                            status = 'inactive',
                            updated_at = NOW(),
                            sync_version = sync_version + 1
                        WHERE id = ?
                    ");
                    $u->bind_param("i", $otherRow['id']);
                    if (!$u->execute()) {
                        $u->close();
                        throw new Exception("Failed clearing counterpart fiber port: " . $conn->error);
                    }
                    $u->close();

                    // history for counterpart
                    $conn->query("INSERT INTO connection_history
                        (user_name, connection_type, source_type, source_id, source_port, target_type, target_id, target_port, action, old_values, new_values)
                        VALUES (
                            '" . $conn->real_escape_string($user) . "',
                            'fiber_to_fiber',
                            'fiber_panel', " . intval($otherRow['panel_id']) . ", " . intval($otherRow['port_number']) . ",
                            'fiber_panel', " . intval($panelId) . ", " . intval($portNo) . ",
                            'deleted',
                            '" . $conn->real_escape_string(json_encode($otherRow, JSON_UNESCAPED_UNICODE)) . "',
                            NULL
                        )");
                }
            }
        }

        // If connected to a switch, clear that relation on this fiber_ports row.
        // Note: we do NOT auto-clear switch-side ports in 'ports' table by default; if desired, implement here.
        // Clear this port now:
        $u2 = $conn->prepare("
            UPDATE fiber_ports
            SET connected_fiber_panel_id = NULL,
                connected_fiber_panel_port = NULL,
                connected_switch_id = NULL,
                connected_switch_port = NULL,
                connection_type = 'inactive',
                connection_details = NULL,
                status = 'inactive',
                updated_at = NOW(),
                sync_version = sync_version + 1
            WHERE id = ?
        ");
        $u2->bind_param("i", $row['id']);
        if (!$u2->execute()) {
            $u2->close();
            throw new Exception("Failed clearing fiber port: " . $conn->error);
        }
        $u2->close();

        // history for this port
        $conn->query("INSERT INTO connection_history
            (user_name, connection_type, source_type, source_id, source_port, target_type, target_id, target_port, action, old_values, new_values)
            VALUES (
                '" . $conn->real_escape_string($user) . "',
                'fiber_to_fiber',
                'fiber_panel', " . intval($panelId) . ", " . intval($portNo) . ",
                'any', 0, 0,
                'deleted',
                '" . $conn->real_escape_string(json_encode($oldValues, JSON_UNESCAPED_UNICODE)) . "',
                NULL
            )");

        $conn->commit();
        jsonResponse(true, "Fiber port disconnected", ['panel_id' => $panelId, 'port' => $portNo]);

    } elseif ($type === 'switch') {
        $switchId = isset($data['switch_id']) ? intval($data['switch_id']) : 0;
        $port = isset($data['port']) ? intval($data['port']) : 0;
        if ($switchId <= 0 || $port <= 0) throw new Exception("Invalid switch_id or port");

        // Find all fiber_ports pointing to this switch/port (should be 0 or 1 in normal infra, but support multiple)
        $s = $conn->prepare("SELECT * FROM fiber_ports WHERE connected_switch_id = ? AND connected_switch_port = ? FOR UPDATE");
        $s->bind_param("ii", $switchId, $port);
        $s->execute();
        $res = $s->get_result();
        $rows = $res->fetch_all(MYSQLI_ASSOC);
        $s->close();

        if (empty($rows)) {
            // nothing to do
            $conn->commit();
            jsonResponse(true, "No fiber port connected to given switch port");
        }

        foreach ($rows as $row) {
            $oldValues = $row;
            // Clear the fiber_ports row
            $u = $conn->prepare("
                UPDATE fiber_ports
                SET connected_switch_id = NULL,
                    connected_switch_port = NULL,
                    connection_type = 'inactive',
                    connection_details = NULL,
                    status = 'inactive',
                    updated_at = NOW(),
                    sync_version = sync_version + 1
                WHERE id = ?
            ");
            $u->bind_param("i", $row['id']);
            if (!$u->execute()) {
                $u->close();
                throw new Exception("Failed clearing fiber_ports for id " . $row['id'] . ": " . $conn->error);
            }
            $u->close();

            // history
            $conn->query("INSERT INTO connection_history
                (user_name, connection_type, source_type, source_id, source_port, target_type, target_id, target_port, action, old_values, new_values)
                VALUES (
                    '" . $conn->real_escape_string($user) . "',
                    'fiber_to_switch',
                    'fiber_panel', " . intval($row['panel_id']) . ", " . intval($row['port_number']) . ",
                    'switch', " . intval($switchId) . ", " . intval($port) . ",
                    'deleted',
                    '" . $conn->real_escape_string(json_encode($oldValues, JSON_UNESCAPED_UNICODE)) . "',
                    NULL
                )");
        }

        $conn->commit();
        jsonResponse(true, "Disconnected fiber port(s) from switch", ['switch_id' => $switchId, 'port' => $port]);

    } else {
        throw new Exception("Unsupported type");
    }

} catch (Exception $e) {
    if (isset($conn) && $conn->in_transaction) {
        @$conn->rollback();
    }
    error_log("disconnectFiberPort error: " . $e->getMessage() . " | payload: " . ($raw ?? ''));
    jsonResponse(false, "Error: " . $e->getMessage());
}

$conn->close();
?>