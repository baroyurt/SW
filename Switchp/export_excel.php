<?php
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

$type = isset($_GET['type']) ? trim($_GET['type']) : 'switches';
$allowed = ['switches', 'racks', 'panels', 'all'];
if (!in_array($type, $allowed)) {
    http_response_code(400);
    exit('Geçersiz tür.');
}

// Output a CSV file
function outputCsv($filename, array $rows) {
    // Strip any characters that could break the Content-Disposition header value
    $filename = preg_replace('/[^A-Za-z0-9_\-\.]/', '_', $filename);
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');

    $out = fopen('php://output', 'w');
    // UTF-8 BOM so Excel recognises encoding
    fwrite($out, "\xEF\xBB\xBF");
    foreach ($rows as $row) {
        fputcsv($out, $row, ';');
    }
    fclose($out);
}

// ─── Switches ─────────────────────────────────────────────────────────────
function getSwitchRows($conn) {
    $rows = [['ID', 'Ad', 'Marka', 'Model', 'Port Sayısı', 'IP Adresi', 'Durum', 'Rack', 'Rack Konum']];
    $res = $conn->query("
        SELECT s.id, s.name, s.brand, s.model, s.ports, s.ip, s.status,
               r.name AS rack_name, r.location AS rack_location
        FROM switches s
        LEFT JOIN racks r ON s.rack_id = r.id
        ORDER BY s.name
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = [
                $row['id'], $row['name'], $row['brand'], $row['model'],
                $row['ports'], $row['ip'], $row['status'],
                $row['rack_name'] ?? '', $row['rack_location'] ?? ''
            ];
        }
    }
    return $rows;
}

// ─── Racks ────────────────────────────────────────────────────────────────
function getRackRows($conn) {
    $rows = [['ID', 'Ad', 'Konum', 'Slot Sayısı', 'Açıklama']];
    $res = $conn->query("SELECT id, name, location, slots, description FROM racks ORDER BY name");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = [$row['id'], $row['name'], $row['location'], $row['slots'], $row['description'] ?? ''];
        }
    }
    return $rows;
}

// ─── Panels (Patch + Fiber) ────────────────────────────────────────────────
function getPanelRows($conn) {
    $rows = [['Tür', 'ID', 'Harf', 'Rack', 'Rack Konum', 'Port Sayısı', 'Açıklama']];
    $res = $conn->query("
        SELECT 'Patch Panel' AS panel_type, pp.id, pp.panel_letter, r.name AS rack_name, r.location, pp.port_count, pp.description
        FROM patch_panels pp
        LEFT JOIN racks r ON pp.rack_id = r.id
        UNION ALL
        SELECT 'Fiber Panel', fp.id, fp.panel_letter, r.name, r.location, fp.port_count, fp.description
        FROM fiber_panels fp
        LEFT JOIN racks r ON fp.rack_id = r.id
        ORDER BY rack_name, panel_letter
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = [
                $row['panel_type'], $row['id'], $row['panel_letter'],
                $row['rack_name'] ?? '', $row['location'] ?? '',
                $row['port_count'] ?? '', $row['description'] ?? ''
            ];
        }
    }
    return $rows;
}

// ─── Ports ────────────────────────────────────────────────────────────────
function getPortRows($conn) {
    $rows = [['Switch', 'Port No', 'Tür', 'Cihaz', 'IP', 'MAC', 'Aktif']];
    $res = $conn->query("
        SELECT s.name AS switch_name, p.port_no, p.type, p.device, p.ip, p.mac,
               CASE WHEN (p.ip IS NOT NULL AND p.ip != '') OR (p.mac IS NOT NULL AND p.mac != '')
                    OR (p.device IS NOT NULL AND p.device != '' AND p.device != 'BOŞ')
                    THEN 'Evet' ELSE 'Hayır' END AS is_active
        FROM ports p
        LEFT JOIN switches s ON p.switch_id = s.id
        ORDER BY s.name, p.port_no
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = [
                $row['switch_name'] ?? '', $row['port_no'], $row['type'],
                $row['device'], $row['ip'], $row['mac'], $row['is_active']
            ];
        }
    }
    return $rows;
}

// ─── Dispatch ─────────────────────────────────────────────────────────────
$date = date('Ymd_His');  // used in all filenames; date() output contains only safe chars

if ($type === 'switches') {
    outputCsv('switches_' . $date . '.csv', getSwitchRows($conn));
} elseif ($type === 'racks') {
    outputCsv('racks_' . $date . '.csv', getRackRows($conn));
} elseif ($type === 'panels') {
    outputCsv('panels_' . $date . '.csv', getPanelRows($conn));
} elseif ($type === 'all') {
    // Produce one multi-section CSV
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="export_all_' . $date . '.csv"');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');

    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");

    fputcsv($out, ['=== SWITCHLER ==='], ';');
    foreach (getSwitchRows($conn) as $row) fputcsv($out, $row, ';');

    fputcsv($out, [], ';');
    fputcsv($out, ['=== RACKLER ==='], ';');
    foreach (getRackRows($conn) as $row) fputcsv($out, $row, ';');

    fputcsv($out, [], ';');
    fputcsv($out, ['=== PANELLER ==='], ';');
    foreach (getPanelRows($conn) as $row) fputcsv($out, $row, ';');

    fputcsv($out, [], ';');
    fputcsv($out, ['=== PORTLAR ==='], ';');
    foreach (getPortRows($conn) as $row) fputcsv($out, $row, ';');

    fclose($out);
}
?>
