<?php
/**
 * Real-Time API for SNMP Monitoring System
 * Provides live updates for alarms, port status, and device connectivity
 */

// Error handling configuration
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/logs/api_errors.log');

session_start();
require_once 'db.php';
require_once 'auth.php';

// Initialize auth
$auth = new Auth($conn);

// Check if user is authenticated
if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

header('Content-Type: application/json');

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'get_recent_alarms':
        getRecentAlarms($conn);
        break;
        
    case 'get_alarm_count':
        getAlarmCount($conn);
        break;
        
    case 'get_port_updates':
        getPortUpdates($conn);
        break;
        
    case 'get_device_status':
        getDeviceStatus($conn);
        break;
        
    case 'check_new_alarms':
        checkNewAlarms($conn);
        break;
        
    default:
        echo json_encode(['error' => 'Invalid action']);
}

/**
 * Get recent alarms (last 5 minutes)
 */
function getRecentAlarms($conn) {
    $since = $_GET['since'] ?? date('Y-m-d H:i:s', strtotime('-5 minutes'));
    
    $query = "SELECT a.*, 
              d.name as device_name, 
              d.ip as device_ip
              FROM alarms a
              LEFT JOIN snmp_devices d ON a.device_id = d.id
              WHERE a.created_at > ?
              AND a.status = 'ACTIVE'
              ORDER BY a.created_at DESC
              LIMIT 50";
              
    $stmt = $conn->prepare($query);
    $stmt->bind_param('s', $since);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $alarms = [];
    while ($row = $result->fetch_assoc()) {
        $alarms[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'alarms' => $alarms,
        'count' => count($alarms),
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}

/**
 * Get active alarm count
 */
function getAlarmCount($conn) {
    $query = "SELECT 
              COUNT(*) as total,
              SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
              SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
              SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
              SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
              FROM alarms 
              WHERE status = 'ACTIVE'";
              
    $result = $conn->query($query);
    $counts = $result->fetch_assoc();
    
    echo json_encode([
        'success' => true,
        'counts' => $counts,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}

/**
 * Get port status updates since last check
 */
function getPortUpdates($conn) {
    $since = $_GET['since'] ?? date('Y-m-d H:i:s', strtotime('-1 minute'));
    
    $query = "SELECT 
              psd.id,
              psd.device_id,
              psd.port_number,
              psd.admin_status,
              psd.oper_status,
              psd.last_change,
              psd.updated_at,
              d.name as device_name
              FROM port_status_data psd
              JOIN snmp_devices d ON psd.device_id = d.id
              WHERE psd.updated_at > ?
              ORDER BY psd.updated_at DESC
              LIMIT 100";
              
    $stmt = $conn->prepare($query);
    $stmt->bind_param('s', $since);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $updates = [];
    while ($row = $result->fetch_assoc()) {
        $updates[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'updates' => $updates,
        'count' => count($updates),
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}

/**
 * Get device connectivity status
 */
function getDeviceStatus($conn) {
    $query = "SELECT 
              id,
              name,
              ip,
              status,
              last_poll_time,
              TIMESTAMPDIFF(SECOND, last_poll_time, NOW()) as seconds_since_poll
              FROM snmp_devices
              ORDER BY name";
              
    $result = $conn->query($query);
    
    $devices = [];
    while ($row = $result->fetch_assoc()) {
        $devices[] = $row;
    }
    
    echo json_encode([
        'success' => true,
        'devices' => $devices,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}

/**
 * Check for new alarms since timestamp
 */
function checkNewAlarms($conn) {
    try {
        $lastCheck = $_GET['last_check'] ?? date('Y-m-d H:i:s', strtotime('-30 seconds'));
        
        // Validate timestamp format
        if (!preg_match('/^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}$/', $lastCheck)) {
            throw new Exception('Invalid timestamp format');
        }
        
        $query = "SELECT 
                  a.id,
                  a.device_id,
                  a.alarm_type,
                  a.severity,
                  a.message,
                  a.created_at,
                  d.name as device_name,
                  d.ip as device_ip,
                  a.port_number,
                  a.old_value,
                  a.new_value
                  FROM alarms a
                  LEFT JOIN snmp_devices d ON a.device_id = d.id
                  WHERE a.created_at > ?
                  AND a.status = 'ACTIVE'
                  ORDER BY a.created_at DESC";
                  
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new Exception('Database prepare error: ' . $conn->error);
        }
        
        $stmt->bind_param('s', $lastCheck);
        if (!$stmt->execute()) {
            throw new Exception('Database execute error: ' . $stmt->error);
        }
        
        $result = $stmt->get_result();
        
        $newAlarms = [];
        while ($row = $result->fetch_assoc()) {
            $newAlarms[] = $row;
        }
        
        echo json_encode([
            'success' => true,
            'has_new' => count($newAlarms) > 0,
            'new_alarms' => $newAlarms,
            'count' => count($newAlarms),
            'timestamp' => date('Y-m-d H:i:s')
        ]);
    } catch (Exception $e) {
        error_log('checkNewAlarms error: ' . $e->getMessage());
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage(),
            'timestamp' => date('Y-m-d H:i:s')
        ]);
    }
}
