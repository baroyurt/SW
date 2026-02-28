<?php
/**
 * Device Import API
 * Handles Excel bulk upload and device registry management
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type');

require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';

// Initialize authentication
$auth = new Auth($conn);

// Get authenticated user
function getAuthenticatedUser($auth) {
    if ($auth->isLoggedIn()) {
        $user = $auth->getUser();
        return $user['username'] ?? 'system';
    }
    return 'system';
}

// Database connection (reuse existing connection from db.php)
function getDBConnection() {
    global $conn;
    if ($conn && $conn->ping()) {
        return $conn;
    }
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($conn->connect_error) {
        die(json_encode(['error' => 'Database connection failed: ' . $conn->connect_error]));
    }
    $conn->set_charset('utf8mb4');
    return $conn;
}

// Normalize MAC address
function normalizeMac($mac) {
    $mac = strtoupper(preg_replace('/[^0-9A-Fa-f]/', '', $mac));
    if (strlen($mac) === 12) {
        return implode(':', str_split($mac, 2));
    }
    return null;
}

// Validate IP address
function validateIP($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

// Handle Excel file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['excel_file'])) {
    $file = $_FILES['excel_file'];
    
    // Validate file
    $allowed_extensions = ['xls', 'xlsx', 'csv'];
    $file_ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    
    if (!in_array($file_ext, $allowed_extensions)) {
        echo json_encode(['error' => 'Invalid file type. Please upload Excel or CSV file.']);
        exit;
    }
    
    // Load library
    if (!file_exists('vendor/autoload.php')) {
        echo json_encode([
            'error' => 'PhpSpreadsheet library not installed. Please run: composer require phpoffice/phpspreadsheet'
        ]);
        exit;
    }
    require_once 'vendor/autoload.php'; // Composer autoload
    
    try {
        $spreadsheet = null;
        
        if ($file_ext === 'csv') {
            $spreadsheet = \PhpOffice\PhpSpreadsheet\IOFactory::load($file['tmp_name']);
        } else {
            $spreadsheet = \PhpOffice\PhpSpreadsheet\IOFactory::load($file['tmp_name']);
        }
        
        $sheet = $spreadsheet->getActiveSheet();
        $rows = $sheet->toArray();
        
        // Get header row to detect format
        $header = array_shift($rows);
        
        // Detect format based on header row
        // New format: "IP Adresi" or similar in first column
        // Old format: "MAC" or similar in first column
        $is_new_format = false;
        
        if (!empty($header)) {
            $first_header = strtolower(trim($header[0] ?? ''));
            // Check if first column is IP-related (new format) or MAC-related (old format)
            if (strpos($first_header, 'ip') !== false || count($header) <= 3) {
                $is_new_format = true;
            }
        }
        
        $conn = getDBConnection();
        $success_count = 0;
        $error_count = 0;
        $errors = [];
        
        // Start transaction
        $conn->begin_transaction();
        
        try {
            $stmt = $conn->prepare("
                INSERT INTO mac_device_registry 
                (mac_address, ip_address, device_name, user_name, location, department, notes, source, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'excel', ?)
                ON DUPLICATE KEY UPDATE
                    ip_address = VALUES(ip_address),
                    device_name = VALUES(device_name),
                    user_name = VALUES(user_name),
                    location = VALUES(location),
                    department = VALUES(department),
                    notes = VALUES(notes),
                    source = 'excel',
                    updated_by = VALUES(created_by)
            ");
            
            foreach ($rows as $index => $row) {
                $row_num = $index + 2; // +2 for header and 0-index
                
                // Parse based on detected format
                if ($is_new_format) {
                    // New simplified format: IP Adresi | Hostname | MAC Adresi
                    $ip = isset($row[0]) ? trim($row[0]) : null;
                    $device_name = isset($row[1]) ? trim($row[1]) : null;
                    $mac = isset($row[2]) ? normalizeMac($row[2]) : null;
                    $user_name = null;
                    $location = null;
                    $department = null;
                    $notes = null;
                } else {
                    // Old format: MAC, IP, Device Name, User, Location, Department, Notes
                    $mac = isset($row[0]) ? normalizeMac($row[0]) : null;
                    $ip = isset($row[1]) ? trim($row[1]) : null;
                    $device_name = isset($row[2]) ? trim($row[2]) : null;
                    $user_name = isset($row[3]) ? trim($row[3]) : null;
                    $location = isset($row[4]) ? trim($row[4]) : null;
                    $department = isset($row[5]) ? trim($row[5]) : null;
                    $notes = isset($row[6]) ? trim($row[6]) : null;
                }
                
                // Validate
                if (!$mac) {
                    $errors[] = "Row $row_num: Invalid MAC address";
                    $error_count++;
                    continue;
                }
                
                if ($ip && !validateIP($ip)) {
                    $errors[] = "Row $row_num: Invalid IP address ($ip)";
                    $error_count++;
                    continue;
                }
                
                if (!$device_name) {
                    $errors[] = "Row $row_num: Hostname is required";
                    $error_count++;
                    continue;
                }
                
                // Insert/Update
                $created_by = getAuthenticatedUser($auth);
                $stmt->bind_param(
                    'ssssssss',
                    $mac, $ip, $device_name, $user_name, 
                    $location, $department, $notes, $created_by
                );
                
                if ($stmt->execute()) {
                    $success_count++;
                } else {
                    $errors[] = "Row $row_num: Database error - " . $stmt->error;
                    $error_count++;
                }
            }
            
            $stmt->close();
            
            // Log import history
            $stmt_history = $conn->prepare("
                INSERT INTO mac_device_import_history 
                (filename, total_rows, success_count, error_count, errors, imported_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            
            $total_rows = count($rows);
            $errors_json = json_encode($errors);
            $imported_by = getAuthenticatedUser($auth);
            
            $stmt_history->bind_param(
                'siiiss',
                $file['name'], $total_rows, $success_count, $error_count, 
                $errors_json, $imported_by
            );
            $stmt_history->execute();
            $stmt_history->close();
            
            $conn->commit();
            
            echo json_encode([
                'success' => true,
                'message' => "Import completed",
                'total_rows' => $total_rows,
                'success_count' => $success_count,
                'error_count' => $error_count,
                'errors' => $errors
            ]);
            
        } catch (Exception $e) {
            $conn->rollback();
            echo json_encode(['error' => 'Import failed: ' . $e->getMessage()]);
        }
        
        $conn->close();
        
    } catch (Exception $e) {
        echo json_encode(['error' => 'Failed to read file: ' . $e->getMessage()]);
    }
    
    exit;
}

// Handle GET requests
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = $_GET['action'] ?? '';
    $conn = getDBConnection();
    
    switch ($action) {
        case 'list':
            // List all devices with pagination and search
            $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
            $limit = isset($_GET['limit']) ? max(1, min(100, (int)$_GET['limit'])) : 10;
            $offset = ($page - 1) * $limit;
            
            $search = isset($_GET['search']) ? trim($_GET['search']) : '';
            $where = '';
            $params = [];
            
            if ($search) {
                $where = "WHERE mac_address LIKE ? OR device_name LIKE ? OR ip_address LIKE ?";
                $search_param = "%$search%";
                $params = [$search_param, $search_param, $search_param];
            }
            
            // Count total
            $count_query = "SELECT COUNT(*) as total FROM mac_device_registry $where";
            $stmt = $conn->prepare($count_query);
            if ($params) {
                $stmt->bind_param('sss', ...$params);
            }
            $stmt->execute();
            $total = $stmt->get_result()->fetch_assoc()['total'];
            $stmt->close();
            
            // Calculate total pages
            $totalPages = $total > 0 ? ceil($total / $limit) : 1;
            
            // Get data
            $query = "
                SELECT * FROM mac_device_registry 
                $where
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            ";
            $stmt = $conn->prepare($query);
            if ($params) {
                $all_params = array_merge($params, [$limit, $offset]);
                $types = str_repeat('s', count($params)) . 'ii';
                $stmt->bind_param($types, ...$all_params);
            } else {
                $stmt->bind_param('ii', $limit, $offset);
            }
            $stmt->execute();
            $result = $stmt->get_result();
            
            $devices = [];
            while ($row = $result->fetch_assoc()) {
                $devices[] = $row;
            }
            $stmt->close();
            
            echo json_encode([
                'success' => true,
                'total' => $total,
                'page' => $page,
                'limit' => $limit,
                'totalPages' => $totalPages,
                'devices' => $devices
            ]);
            break;
        
        case 'get':
            // Get single device
            $mac = isset($_GET['mac']) ? normalizeMac($_GET['mac']) : null;
            
            if (!$mac) {
                echo json_encode(['error' => 'MAC address required']);
                break;
            }
            
            $stmt = $conn->prepare("SELECT * FROM mac_device_registry WHERE mac_address = ?");
            $stmt->bind_param('s', $mac);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($row = $result->fetch_assoc()) {
                echo json_encode(['success' => true, 'device' => $row]);
            } else {
                echo json_encode(['error' => 'Device not found']);
            }
            $stmt->close();
            break;
        
        case 'history':
            // Get import history
            $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
            
            $stmt = $conn->prepare("
                SELECT * FROM mac_device_import_history 
                ORDER BY import_date DESC 
                LIMIT ?
            ");
            $stmt->bind_param('i', $limit);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $history = [];
            while ($row = $result->fetch_assoc()) {
                $history[] = $row;
            }
            $stmt->close();
            
            echo json_encode(['success' => true, 'history' => $history]);
            break;
        
        default:
            echo json_encode(['error' => 'Invalid action']);
    }
    
    $conn->close();
    exit;
}

// Handle POST - Manual entry and other actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_FILES['excel_file'])) {
    $data = json_decode(file_get_contents('php://input'), true);
    // Check for action in query params first, then in JSON body
    $action = $_GET['action'] ?? ($data['action'] ?? '');
    
    if ($action === 'manual_add') {
        $ip = isset($data['ip_address']) ? trim($data['ip_address']) : null;
        $hostname = isset($data['hostname']) ? trim($data['hostname']) : null;
        $mac = isset($data['mac_address']) ? normalizeMac($data['mac_address']) : null;
        
        // Validate inputs
        $errors = [];
        
        if (!$mac) {
            $errors[] = 'Invalid MAC address format';
        }
        
        if (!$ip || !validateIP($ip)) {
            $errors[] = 'Invalid IP address format';
        }
        
        if (!$hostname) {
            $errors[] = 'Hostname is required';
        }
        
        if (count($errors) > 0) {
            echo json_encode(['success' => false, 'errors' => $errors]);
            exit;
        }
        
        $conn = getDBConnection();
        
        try {
            $stmt = $conn->prepare("
                INSERT INTO mac_device_registry 
                (mac_address, ip_address, device_name, source, created_by)
                VALUES (?, ?, ?, 'manual', ?)
                ON DUPLICATE KEY UPDATE
                    ip_address = VALUES(ip_address),
                    device_name = VALUES(device_name),
                    source = 'manual',
                    updated_by = VALUES(created_by)
            ");
            
            $created_by = getAuthenticatedUser($auth);
            $stmt->bind_param('ssss', $mac, $ip, $hostname, $created_by);
            
            if ($stmt->execute()) {
                echo json_encode([
                    'success' => true,
                    'message' => 'Device added successfully',
                    'device' => [
                        'mac_address' => $mac,
                        'ip_address' => $ip,
                        'device_name' => $hostname
                    ]
                ]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Database error: ' . $stmt->error]);
            }
            
            $stmt->close();
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        
        $conn->close();
        exit;
    }
    
    // Update existing device
    if ($action === 'update') {
        $originalMac = isset($data['original_mac']) ? normalizeMac($data['original_mac']) : null;
        $newMac = isset($data['mac_address']) ? normalizeMac($data['mac_address']) : null;
        $ip = isset($data['ip_address']) ? trim($data['ip_address']) : null;
        $hostname = isset($data['device_name']) ? trim($data['device_name']) : null;
        
        // Validate inputs
        $errors = [];
        
        if (!$originalMac) {
            $errors[] = 'Original MAC address is required';
        }
        
        if (!$newMac) {
            $errors[] = 'Invalid new MAC address format';
        }
        
        if ($ip && !validateIP($ip)) {
            $errors[] = 'Invalid IP address format';
        }
        
        if (!$hostname) {
            $errors[] = 'Hostname is required';
        }
        
        if (count($errors) > 0) {
            echo json_encode(['success' => false, 'error' => implode(', ', $errors)]);
            exit;
        }
        
        $conn = getDBConnection();
        
        try {
            // If MAC changed, delete old record and insert new one
            if ($originalMac !== $newMac) {
                // Delete old record
                $stmt = $conn->prepare("DELETE FROM mac_device_registry WHERE mac_address = ?");
                $stmt->bind_param('s', $originalMac);
                $stmt->execute();
                $stmt->close();
            }
            
            // Insert or update with new data
            $stmt = $conn->prepare("
                INSERT INTO mac_device_registry 
                (mac_address, ip_address, device_name, source, created_by)
                VALUES (?, ?, ?, 'manual', ?)
                ON DUPLICATE KEY UPDATE
                    ip_address = VALUES(ip_address),
                    device_name = VALUES(device_name),
                    source = 'manual',
                    updated_by = VALUES(created_by)
            ");
            
            $updated_by = getAuthenticatedUser($auth);
            $stmt->bind_param('ssss', $newMac, $ip, $hostname, $updated_by);
            
            if ($stmt->execute()) {
                echo json_encode([
                    'success' => true,
                    'message' => 'Device updated successfully',
                    'device' => [
                        'mac_address' => $newMac,
                        'ip_address' => $ip,
                        'device_name' => $hostname
                    ]
                ]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Database error: ' . $stmt->error]);
            }
            
            $stmt->close();
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        
        $conn->close();
        exit;
    }
    
    // Handle apply_to_ports action
    if ($action === 'apply_to_ports') {
        $conn = getDBConnection();
        
        try {
            // Get all devices from registry
            $result = $conn->query("
                SELECT mac_address, ip_address, device_name 
                FROM mac_device_registry 
                WHERE mac_address IS NOT NULL 
                AND ip_address IS NOT NULL 
                AND device_name IS NOT NULL
            ");
            
            if (!$result) {
                echo json_encode(['success' => false, 'error' => 'Database query failed']);
                exit;
            }
            
            $updated_count = 0;
            
            // For each device, find and update matching ports
            while ($device = $result->fetch_assoc()) {
                $mac = $device['mac_address'];
                $ip = $device['ip_address'];
                $hostname = $device['device_name'];
                
                // Normalize MAC for comparison (remove colons, lowercase)
                $macNormalized = strtolower(str_replace(':', '', $mac));
                
                // Update ports table (same as Port Edit uses)
                // Update ip and connection_info columns
                $updateStmt = $conn->prepare("
                    UPDATE ports 
                    SET ip = ?, 
                        connection_info = ?
                    WHERE LOWER(REPLACE(mac, ':', '')) = ?
                    AND mac IS NOT NULL 
                    AND mac != ''
                ");
                
                if ($updateStmt) {
                    $updateStmt->bind_param('sss', $ip, $hostname, $macNormalized);
                    $updateStmt->execute();
                    $updated_count += $updateStmt->affected_rows;
                    $updateStmt->close();
                }
            }
            
            $result->close();
            
            echo json_encode([
                'success' => true,
                'updated_count' => $updated_count,
                'message' => "$updated_count port description(s) updated with Device Import data"
            ]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        
        $conn->close();
        exit;
    }
}

// Handle DELETE
if ($_SERVER['REQUEST_METHOD'] === 'DELETE' || ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['_method']) && $_GET['_method'] === 'DELETE')) {
    $mac = isset($_GET['mac']) ? normalizeMac($_GET['mac']) : null;
    
    if (!$mac) {
        echo json_encode(['error' => 'MAC address required']);
        exit;
    }
    
    $conn = getDBConnection();
    $stmt = $conn->prepare("DELETE FROM mac_device_registry WHERE mac_address = ?");
    $stmt->bind_param('s', $mac);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Device deleted']);
    } else {
        echo json_encode(['error' => 'Failed to delete device']);
    }
    
    $stmt->close();
    $conn->close();
    exit;
}

echo json_encode(['error' => 'Invalid request method']);
?>
