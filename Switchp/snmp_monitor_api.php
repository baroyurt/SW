<?php
/**
 * SNMP Monitoring API
 * Backend API for SNMP monitoring dashboard
 */

session_start();
require_once 'db.php';
require_once 'auth.php';

// Initialize auth
$auth = new Auth($conn);

// Check if user is authenticated
if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

header('Content-Type: application/json');

$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'check_worker':
            echo json_encode(checkWorkerStatus());
            break;
            
        case 'switch_stats':
            echo json_encode(getSwitchStats($conn));
            break;
            
        case 'config_status':
            echo json_encode(getConfigStatus());
            break;
            
        case 'recent_data':
            echo json_encode(getRecentData($conn));
            break;
            
        case 'recent_logs':
            echo json_encode(getRecentLogs());
            break;
            
        case 'test_connection':
            echo json_encode(testConnection($conn));
            break;
            
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid action']);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

/**
 * Check if SNMP Worker service is running
 */
function checkWorkerStatus() {
    $result = [
        'running' => false,
        'last_run' => null,
        'data_count' => 0
    ];
    
    // Check if service is running on Windows
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        $output = [];
        exec('sc query SNMPWorker 2>&1', $output, $returnCode);
        
        $serviceOutput = implode("\n", $output);
        if (strpos($serviceOutput, 'RUNNING') !== false) {
            $result['running'] = true;
        }
    } else {
        // Linux/Unix - check systemd service
        exec('systemctl is-active snmp-worker 2>&1', $output, $returnCode);
        if ($returnCode === 0 && trim($output[0]) === 'active') {
            $result['running'] = true;
        }
    }
    
    // Check log file for last run time
    $logFile = dirname(__DIR__) . '/snmp_worker/logs/snmp_worker.log';
    if (file_exists($logFile)) {
        $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!empty($lines)) {
            $lastLine = end($lines);
            // Extract timestamp from log line
            if (preg_match('/\[([\d\-\s:]+)\]/', $lastLine, $matches)) {
                $result['last_run'] = $matches[1];
            }
        }
    }
    
    return $result;
}

/**
 * Get switch statistics from database
 */
function getSwitchStats($conn) {
    $stats = [
        'total' => 0,
        'snmp_enabled' => 0
    ];
    
    try {
        // Total switches
        $stmt = $conn->query("SELECT COUNT(*) as total FROM switches");
        if ($stmt && $row = $stmt->fetch_assoc()) {
            $stats['total'] = $row['total'];
        }
        
        // SNMP enabled switches (assume all are enabled for SNMP if they have IP)
        $stmt = $conn->query("SELECT COUNT(*) as count FROM switches WHERE ip IS NOT NULL AND ip != ''");
        if ($stmt && $row = $stmt->fetch_assoc()) {
            $stats['snmp_enabled'] = $row['count'];
        }
    } catch (Exception $e) {
        error_log("Switch stats error: " . $e->getMessage());
    }
    
    return $stats;
}

/**
 * Get SNMP config status
 */
function getConfigStatus() {
    $configPath = dirname(__DIR__) . '/snmp_worker/config/config.yml';
    
    $status = [
        'exists' => file_exists($configPath),
        'switches_count' => 0,
        'snmp_version' => 'v3'
    ];
    
    if ($status['exists']) {
        try {
            $configContent = file_get_contents($configPath);
            
            // Count switches in config
            preg_match_all('/^\s*-\s+name:/m', $configContent, $matches);
            $status['switches_count'] = count($matches[0]);
            
            // Get SNMP version
            if (preg_match('/version:\s*["\']?(v\d)["\']?/i', $configContent, $matches)) {
                $status['snmp_version'] = $matches[1];
            }
        } catch (Exception $e) {
            error_log("Config parse error: " . $e->getMessage());
        }
    }
    
    return $status;
}

/**
 * Get recent SNMP data from database
 */
function getRecentData($conn) {
    $data = [];
    
    try {
        // Get recent port data from snmp_ports table
        $sql = "SELECT 
                    s.name as switch_name,
                    sp.port_name,
                    sp.admin_status,
                    sp.oper_status,
                    sp.speed,
                    sp.last_updated
                FROM snmp_ports sp
                JOIN switches s ON sp.switch_id = s.id
                ORDER BY sp.last_updated DESC
                LIMIT 20";
        
        $stmt = $conn->query($sql);
        if ($stmt) {
            while ($row = $stmt->fetch_assoc()) {
                $data[] = [
                    'switch_name' => $row['switch_name'],
                    'port_name' => $row['port_name'],
                    'status' => $row['oper_status'] ?: $row['admin_status'],
                    'speed' => $row['speed'] ? formatSpeed($row['speed']) : 'N/A',
                    'last_update' => $row['last_updated'] ?: 'N/A'
                ];
            }
        }
    } catch (Exception $e) {
        error_log("Recent data error: " . $e->getMessage());
    }
    
    return ['data' => $data];
}

/**
 * Format speed value
 */
function formatSpeed($speed) {
    if ($speed >= 1000000000) {
        return round($speed / 1000000000, 1) . ' Gbps';
    } elseif ($speed >= 1000000) {
        return round($speed / 1000000) . ' Mbps';
    } elseif ($speed >= 1000) {
        return round($speed / 1000) . ' Kbps';
    }
    return $speed . ' bps';
}

/**
 * Get recent log entries
 */
function getRecentLogs() {
    $logs = [];
    $logFile = dirname(__DIR__) . '/snmp_worker/logs/snmp_worker.log';
    
    if (file_exists($logFile)) {
        $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $recentLines = array_slice($lines, -50); // Last 50 lines
        
        foreach ($recentLines as $line) {
            // Parse log line
            if (preg_match('/\[([\d\-\s:]+)\]\s+\[(\w+)\]\s+(.+)/', $line, $matches)) {
                $logs[] = [
                    'timestamp' => $matches[1],
                    'level' => strtolower($matches[2]),
                    'message' => $matches[3]
                ];
            } else {
                // Simple format
                $logs[] = [
                    'timestamp' => date('Y-m-d H:i:s'),
                    'level' => 'info',
                    'message' => $line
                ];
            }
        }
    }
    
    return ['logs' => array_reverse($logs)]; // Most recent first
}

/**
 * Test all connections
 */
function testConnection($conn) {
    $configPath = dirname(__DIR__) . '/snmp_worker/config/config.yml';
    
    $result = [
        'success' => true,
        'config_exists' => file_exists($configPath),
        'database_connected' => false,
        'snmp_configured' => false
    ];
    
    // Test database
    try {
        $stmt = $conn->query("SELECT 1");
        $result['database_connected'] = ($stmt !== false);
    } catch (Exception $e) {
        $result['success'] = false;
        $result['error'] = 'Database connection failed: ' . $e->getMessage();
        return $result;
    }
    
    // Check SNMP config
    if ($result['config_exists']) {
        $configContent = file_get_contents($configPath);
        $result['snmp_configured'] = (strpos($configContent, 'switches:') !== false);
    }
    
    if (!$result['config_exists'] || !$result['snmp_configured']) {
        $result['success'] = false;
        $result['error'] = 'SNMP configuration is missing or incomplete';
    }
    
    return $result;
}
