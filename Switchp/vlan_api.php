<?php
/**
 * VLAN Names API
 * Returns VLAN names and helps with VLAN-based filtering
 */

require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

header('Content-Type: application/json');

$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'get_vlan_names':
            getVLANNames($conn);
            break;
            
        case 'get_ports_by_vlan':
            $vlanId = isset($_GET['vlan_id']) ? intval($_GET['vlan_id']) : 0;
            getPortsByVLAN($conn, $vlanId);
            break;
            
        case 'get_vlan_summary':
            getVLANSummary($conn);
            break;
            
        default:
            throw new Exception('Invalid action');
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}

/**
 * Get all VLAN names
 */
function getVLANNames($conn) {
    $sql = "SELECT vlan_id, vlan_name, description, color 
            FROM vlan_names 
            ORDER BY vlan_id";
    
    $result = $conn->query($sql);
    $vlans = [];
    
    while ($row = $result->fetch_assoc()) {
        $vlans[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'vlans' => $vlans
    ]);
}

/**
 * Get ports filtered by VLAN
 */
function getPortsByVLAN($conn, $vlanId) {
    if ($vlanId === 0) {
        // Get all ports
        $sql = "SELECT p.*, s.name as switch_name, s.ip as switch_ip, vn.vlan_name, vn.color as vlan_color
                FROM ports p
                LEFT JOIN switches s ON p.switch_id = s.id
                LEFT JOIN vlan_names vn ON p.vlan = vn.vlan_id
                ORDER BY s.name, p.port_no";
    } else {
        // Get ports for specific VLAN
        $sql = "SELECT p.*, s.name as switch_name, s.ip as switch_ip, vn.vlan_name, vn.color as vlan_color
                FROM ports p
                LEFT JOIN switches s ON p.switch_id = s.id
                LEFT JOIN vlan_names vn ON p.vlan = vn.vlan_id
                WHERE p.vlan = ?
                ORDER BY s.name, p.port_no";
    }
    
    if ($vlanId === 0) {
        $result = $conn->query($sql);
    } else {
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $vlanId);
        $stmt->execute();
        $result = $stmt->get_result();
    }
    
    $ports = [];
    while ($row = $result->fetch_assoc()) {
        $ports[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'vlan_id' => $vlanId,
        'ports' => $ports,
        'count' => count($ports)
    ]);
}

/**
 * Get VLAN summary with port counts
 */
function getVLANSummary($conn) {
    $sql = "SELECT 
                vn.vlan_id,
                vn.vlan_name,
                vn.description,
                vn.color,
                COUNT(p.id) as port_count,
                SUM(CASE WHEN p.type != 'EMPTY' THEN 1 ELSE 0 END) as active_ports
            FROM vlan_names vn
            LEFT JOIN ports p ON vn.vlan_id = p.vlan
            GROUP BY vn.vlan_id, vn.vlan_name, vn.description, vn.color
            ORDER BY vn.vlan_id";
    
    $result = $conn->query($sql);
    $summary = [];
    
    while ($row = $result->fetch_assoc()) {
        $summary[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'summary' => $summary
    ]);
}
?>
