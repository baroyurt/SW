<?php
/**
 * importExcel.php
 *
 * Import JSON (converted from Excel) into DB, ensuring Connection field is saved.
 *
 * Expected input: JSON array of switch rows, each row example:
 * {
 *   "name": "SW26 -VIP",
 *   "brand": "Cisco",
 *   "model": "X",
 *   "ports": 48,
 *   "rack": "RUBY",
 *   "ip": "172.18.50.1",
 *   "ports_data": [
 *      { "port": "Giga-1", "type":"DEVICE", "device":"DEVICE", "ip":"172.18.50.87", "mac":"e0:73:e7:2c:f9:c9", "connection":"PitBreaklist02" },
 *      ...
 *   ]
 * }
 *
 * This script:
 * - Creates/updates switches
 * - Ensures ports exist for switch (create missing numbered ports up to ports count)
 * - For each port row, inserts/updates ports table and crucially stores:
 *     - multiple_connections (JSON) if input is JSON list
 *     - connection_info (JSON) if parsed JSON details exist
 *     - connection_info_preserved (raw text) always saved when available
 *
 * NOTE: This script uses escaped direct SQL for simplicity & cross-PHP compatibility.
 *       Make a DB backup before running on production.
 */

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/import_errors.log');

header('Content-Type: application/json; charset=utf-8');

function jsonError($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(['status' => 'error', 'message' => $msg]);
    exit;
}

$raw = file_get_contents('php://input');
if (empty($raw)) jsonError('Boş istek göderildi');

$data = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    jsonError('JSON parse error: ' . json_last_error_msg());
}
if (!is_array($data)) jsonError('Beklenen dizi formatında veri yok');

/**
 * Helper: parse port number from label.
 * e.g. "Giga-1" -> 1, "Port 5" -> 5, "5" -> 5.
 */
function parsePortNumber($label) {
    if ($label === null) return null;
    $label = trim((string)$label);
    if ($label === '') return null;
    if (is_numeric($label)) return intval($label);
    // match trailing number
    if (preg_match('/(\d+)(?!.*\d)/', $label, $m)) {
        return intval($m[1]);
    }
    return null;
}

/**
 * Normalize ports count to standard switch sizes.
 * - <=24 => 24
 * - <=28 => 28 (24 + 4 fiber)
 * - <=48 => 48
 * - <=52 => 52 (48 + 4 fiber)
 * otherwise round up to nearest multiple of 4.
 */
function normalize_ports_count($n) {
    $n = intval($n);
    if ($n <= 0) return 48;
    if ($n <= 24) return 24;
    if ($n <= 28) return 28; // 24 + 4 fiber
    if ($n <= 48) return 48;
    if ($n <= 52) return 52; // 48 + 4 fiber
    // fallback: round up to nearest multiple of 4
    return ceil($n / 4) * 4;
}

// DB connection (adjust credentials if needed)
$host = "localhost";
$user = "root";
$pass = "";
$db   = "switchdb";

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    jsonError('DB bağlantı hatası: ' . $conn->connect_error, 500);
}
$conn->set_charset('utf8mb4');

/**
 * Ensure ports table has the necessary columns to store connection info.
 * If they are missing, we detect and return error to ask user to run ALTER.
 */
$requiredCols = ['connection_info', 'connection_info_preserved', 'multiple_connections'];
$missing = [];
$resCols = $conn->query("SHOW COLUMNS FROM ports");
$existingCols = [];
if ($resCols) {
    while ($r = $resCols->fetch_assoc()) $existingCols[] = $r['Field'];
} else {
    jsonError('SHOW COLUMNS failed: ' . $conn->error, 500);
}
foreach ($requiredCols as $col) {
    if (!in_array($col, $existingCols)) $missing[] = $col;
}
if (!empty($missing)) {
    jsonError('Eksik sütunlar: ' . implode(', ', $missing) . '. Lütfen aşağıdaki SQL\'i çalıştırın ve tekrar deneyin: ALTER TABLE ports ADD COLUMN connection_info TEXT, ADD COLUMN connection_info_preserved TEXT, ADD COLUMN multiple_connections TEXT;', 500);
}

// Stats
$stats = [
    'processed_switches' => 0,
    'created_switches' => 0,
    'updated_switches' => 0,
    'created_ports' => 0,
    'updated_ports' => 0,
    'skipped_rows' => 0
];

try {
    foreach ($data as $row) {
        if (!isset($row['name'])) {
            $stats['skipped_rows']++;
            continue;
        }

        $switchName = trim($row['name']);
        $brand = isset($row['brand']) ? trim($row['brand']) : '';
        $model = isset($row['model']) ? trim($row['model']) : '';
        // normalize portsCount using helper for common switch sizes
        $portsCount = isset($row['ports']) ? normalize_ports_count($row['ports']) : 48;
        $rackName = isset($row['rack']) ? trim($row['rack']) : null;
        $ip = isset($row['ip']) ? trim($row['ip']) : '';
        $status = isset($row['status']) ? trim($row['status']) : 'online';

        // Find or create rack id (if rackName provided)
        $rackId = null;
        if (!empty($rackName)) {
            $stmt = $conn->prepare("SELECT id FROM racks WHERE name = ? LIMIT 1");
            $stmt->bind_param("s", $rackName);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($rowRack = $res->fetch_assoc()) {
                $rackId = intval($rowRack['id']);
            } else {
                $stmtIns = $conn->prepare("INSERT INTO racks (name, location) VALUES (?, ?)");
                $loc = $rackName;
                $stmtIns->bind_param("ss", $rackName, $loc);
                $stmtIns->execute();
                $rackId = $conn->insert_id;
                $stmtIns->close();
            }
            $stmt->close();
        }

        // Check if switch exists by name
        $stmt = $conn->prepare("SELECT id, ports FROM switches WHERE name = ? LIMIT 1");
        $stmt->bind_param("s", $switchName);
        $stmt->execute();
        $res = $stmt->get_result();
        $switchId = null;
        if ($sw = $res->fetch_assoc()) {
            $switchId = intval($sw['id']);
            // update ports count if differs
            if ($sw['ports'] != $portsCount) {
                $u = $conn->prepare("UPDATE switches SET ports = ? WHERE id = ?");
                $u->bind_param("ii", $portsCount, $switchId);
                $u->execute();
                $u->close();
                $stats['updated_switches']++;
            }
        } else {
            // insert switch
            $ins = $conn->prepare("INSERT INTO switches (name, brand, model, ports, status, rack_id, ip, position_in_rack) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)");
            $ins->bind_param("sssissi", $switchName, $brand, $model, $portsCount, $status, $rackId, $ip);
            if (!$ins->execute()) {
                // continue but log
                error_log("Switch insert failed for {$switchName}: " . $ins->error);
                $ins->close();
                $stats['skipped_rows']++;
                continue;
            }
            $switchId = $conn->insert_id;
            $ins->close();
            $stats['created_switches']++;
        }
        $stmt->close();
        $stats['processed_switches']++;

        // Ensure numeric ports exist up to $portsCount
        // Get existing port numbers for that switch
        $exist = $conn->query("SELECT port_no FROM ports WHERE switch_id = " . intval($switchId));
        $existingPorts = [];
        if ($exist) {
            while ($p = $exist->fetch_assoc()) $existingPorts[intval($p['port_no'])] = true;
        }

        // Create missing ports (simple BOŞ defaults)
        for ($i = 1; $i <= $portsCount; $i++) {
            if (!isset($existingPorts[$i])) {
                $sql = "INSERT INTO ports (switch_id, port_no, type, device, ip, mac, rack_port, is_hub, hub_name, multiple_connections, device_count, sync_version) VALUES (" . intval($switchId) . ", " . intval($i) . ", 'BOŞ', '', '', '', 0, 0, NULL, NULL, 0, 1)";
                if ($conn->query($sql)) $stats['created_ports']++;
            }
        }

        // Handle ports_data if present
        if (isset($row['ports_data']) && is_array($row['ports_data'])) {
            foreach ($row['ports_data'] as $portRow) {
                // Map fields (case-insensitive)
                $portLabel = $portRow['port'] ?? ($portRow['Port'] ?? null);
                $portNo = parsePortNumber($portLabel);
                if (!$portNo) {
                    // try 'port_no' key
                    $portNo = isset($portRow['port_no']) ? intval($portRow['port_no']) : null;
                    if (!$portNo) { $stats['skipped_rows']++; continue; }
                }

                $type = isset($portRow['type']) ? trim($portRow['type']) : (isset($portRow['Description']) ? trim($portRow['Description']) : 'BOŞ');
                $device = isset($portRow['device']) ? trim($portRow['device']) : (isset($portRow['Description']) ? trim($portRow['Description']) : '');
                $portIp = isset($portRow['ip']) ? trim($portRow['ip']) : '';
                $mac = isset($portRow['mac']) ? trim($portRow['mac']) : '';
                // Connection column may be named 'connection' or 'Connection'
                $connectionRaw = isset($portRow['connection']) ? trim($portRow['connection']) : (isset($portRow['Connection']) ? trim($portRow['Connection']) : '');

                // Normalize connection: detect JSON multi-record or plain text
                $multipleConnectionsJson = null;
                $connectionInfoJson = null; // JSON details
                $connectionPreserved = $connectionRaw;

                if ($connectionRaw !== '') {
                    $trim = ltrim($connectionRaw);
                    if ($trim !== '' && ($trim[0] === '[' || $trim[0] === '{')) {
                        $parsed = json_decode($connectionRaw, true);
                        if (json_last_error() === JSON_ERROR_NONE && is_array($parsed)) {
                            $multipleConnectionsJson = json_encode($parsed, JSON_UNESCAPED_UNICODE);
                            $connectionInfoJson = $multipleConnectionsJson;
                        } else {
                            // not valid JSON -> keep as preserved text
                        }
                    } else {
                        // plain text. If it contains multiple entries separated by commas/newlines, convert to JSON array
                        if (strpos($connectionRaw, "\n") !== false || strpos($connectionRaw, ",") !== false || strpos($connectionRaw, ";") !== false) {
                            $parts = preg_split('/[\r\n,;]+/', $connectionRaw);
                            $parts = array_values(array_filter(array_map('trim', $parts), function($v){ return $v !== ''; }));
                            if (count($parts) > 1) {
                                $arr = [];
                                foreach ($parts as $p) $arr[] = ['device'=> $p];
                                $multipleConnectionsJson = json_encode($arr, JSON_UNESCAPED_UNICODE);
                                $connectionInfoJson = $multipleConnectionsJson;
                            }
                        }
                    }
                }

                // Decide hub detection: if multiple connections exist -> is_hub = 1
                $isHub = ($multipleConnectionsJson !== null) ? 1 : 0;
                $hubName = $isHub ? ($device ?: null) : null;
                $deviceCount = 0;
                if ($multipleConnectionsJson) {
                    $tmp = json_decode($multipleConnectionsJson, true);
                    $deviceCount = is_array($tmp) ? count($tmp) : 0;
                }

                // Prepare escaped values
                $esc_type = $conn->real_escape_string($type);
                $esc_device = $conn->real_escape_string($device);
                $esc_ip = $conn->real_escape_string($portIp);
                $esc_mac = $conn->real_escape_string($mac);
                $esc_conn_json = $connectionInfoJson ? $conn->real_escape_string($connectionInfoJson) : null;
                $esc_conn_preserved = $connectionPreserved ? $conn->real_escape_string($connectionPreserved) : null;
                $esc_multiple = $multipleConnectionsJson ? $conn->real_escape_string($multipleConnectionsJson) : null;
                $esc_hub_name = $hubName ? $conn->real_escape_string($hubName) : null;

                // Check existing port row
                $resPort = $conn->query("SELECT id FROM ports WHERE switch_id = " . intval($switchId) . " AND port_no = " . intval($portNo) . " LIMIT 1");
                if ($resPort && $rowPort = $resPort->fetch_assoc()) {
                    // Update but DO NOT clear connected_panel_id/connected_panel_port unless user wants to (we preserve)
                    $sql = "UPDATE ports SET
                        type = '{$esc_type}',
                        device = '{$esc_device}',
                        ip = '{$esc_ip}',
                        mac = '{$esc_mac}',
                        is_hub = " . intval($isHub) . ",
                        hub_name = " . ($esc_hub_name !== null ? "'{$esc_hub_name}'" : "NULL") . ",
                        multiple_connections = " . ($esc_multiple !== null ? "'{$esc_multiple}'" : "NULL") . ",
                        device_count = " . intval($deviceCount) . ",
                        connection_info = " . ($esc_conn_json !== null ? "'{$esc_conn_json}'" : "NULL") . ",
                        connection_info_preserved = " . ($esc_conn_preserved !== null ? "'{$esc_conn_preserved}'" : "NULL") . ",
                        updated_at = NOW()
                        WHERE switch_id = " . intval($switchId) . " AND port_no = " . intval($portNo);

                    if (!$conn->query($sql)) {
                        error_log("Port update failed switch {$switchId} port {$portNo}: " . $conn->error);
                    } else {
                        $stats['updated_ports']++;
                    }
                } else {
                    // Insert new port row
                    $sql = "INSERT INTO ports (switch_id, port_no, type, device, ip, mac, rack_port, is_hub, hub_name, multiple_connections, device_count, connection_info, connection_info_preserved, sync_version)
                        VALUES (" . intval($switchId) . ",
                                " . intval($portNo) . ",
                                '{$esc_type}', '{$esc_device}', '{$esc_ip}', '{$esc_mac}',
                                0, " . intval($isHub) . ",
                                " . ($esc_hub_name !== null ? "'{$esc_hub_name}'" : "NULL") . ",
                                " . ($esc_multiple !== null ? "'{$esc_multiple}'" : "NULL") . ",
                                " . intval($deviceCount) . ",
                                " . ($esc_conn_json !== null ? "'{$esc_conn_json}'" : "NULL") . ",
                                " . ($esc_conn_preserved !== null ? "'{$esc_conn_preserved}'" : "NULL") . ",
                                1
                        )";
                    if (!$conn->query($sql)) {
                        error_log("Port insert failed switch {$switchId} port {$portNo}: " . $conn->error . " SQL: {$sql}");
                    } else {
                        $stats['created_ports']++;
                    }
                }
            } // end foreach ports_data
        } // end if ports_data
    } // end foreach switches

    echo json_encode([
        'status' => 'ok',
        'message' => 'Import tamamlandı',
        'stats' => $stats
    ]);

} catch (Exception $e) {
    error_log("Import exception: " . $e->getMessage());
    jsonError('Import sırasında hata: ' . $e->getMessage(), 500);
} finally {
    if (isset($conn) && $conn instanceof mysqli) $conn->close();
}
?>