<?php
/**
 * SNMP Test API
 * Backend for testing SNMP connectivity
 */

header('Content-Type: application/json');
error_reporting(E_ALL);
ini_set('display_errors', 0); // Don't display errors in JSON response

// Get POST data
$input = file_get_contents('php://input');
$data = json_decode($input, true);

$response = ['success' => false];

try {
    $action = $data['action'] ?? '';
    
    if ($action === 'test_switch') {
        $host = $data['host'] ?? '';
        $username = $data['username'] ?? '';
        $authProtocol = $data['auth_protocol'] ?? 'SHA';
        $authPassword = $data['auth_password'] ?? '';
        $privProtocol = $data['priv_protocol'] ?? 'AES';
        $privPassword = $data['priv_password'] ?? '';
        
        if (empty($host)) {
            throw new Exception('Host gerekli');
        }
        
        // Check if SNMP extension is loaded
        if (!extension_loaded('snmp')) {
            throw new Exception('PHP SNMP extension yüklü değil. Lütfen php-snmp paketini yükleyin.');
        }
        
        // Test 1: Ping test
        $pingSuccess = false;
        $pingOutput = [];
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            exec("ping -n 1 -w 1000 $host", $pingOutput, $pingReturn);
        } else {
            exec("ping -c 1 -W 1 $host", $pingOutput, $pingReturn);
        }
        $pingSuccess = ($pingReturn === 0);
        
        $response['ping_success'] = $pingSuccess;
        $response['ping_output'] = implode("\n", $pingOutput);
        
        if (!$pingSuccess) {
            throw new Exception("Switch IP adresine ping atılamadı ($host). Switch açık mı? Ağ bağlantısı var mı?");
        }
        
        // Test 2: SNMP Connection
        $timeout = 2000000; // 2 seconds in microseconds
        $retries = 1;
        
        // Set SNMP timeout and retries
        snmp_set_valueretrieval(SNMP_VALUE_PLAIN);
        snmp_set_quick_print(true);
        
        // Try to get system description (sysDescr OID: 1.3.6.1.2.1.1.1.0)
        $sysDescr = @snmp3_get(
            $host,
            $username,
            'authPriv',  // Security level
            $authProtocol,
            $authPassword,
            $privProtocol,
            $privPassword,
            '1.3.6.1.2.1.1.1.0',  // sysDescr
            $timeout,
            $retries
        );
        
        if ($sysDescr === false) {
            $error = error_get_last();
            throw new Exception('SNMP v3 bağlantısı başarısız. Hata: ' . ($error['message'] ?? 'Bilinmeyen hata'));
        }
        
        // Try to get more system info
        $snmpData = [
            'sysDescr' => $sysDescr,
            'sysName' => @snmp3_get($host, $username, 'authPriv', $authProtocol, $authPassword, $privProtocol, $privPassword, '1.3.6.1.2.1.1.5.0', $timeout, $retries),
            'sysUpTime' => @snmp3_get($host, $username, 'authPriv', $authProtocol, $authPassword, $privProtocol, $privPassword, '1.3.6.1.2.1.1.3.0', $timeout, $retries),
            'sysContact' => @snmp3_get($host, $username, 'authPriv', $authProtocol, $authPassword, $privProtocol, $privPassword, '1.3.6.1.2.1.1.4.0', $timeout, $retries),
            'sysLocation' => @snmp3_get($host, $username, 'authPriv', $authProtocol, $authPassword, $privProtocol, $privPassword, '1.3.6.1.2.1.1.6.0', $timeout, $retries),
        ];
        
        // Try to get interface count
        $ifNumber = @snmp3_get($host, $username, 'authPriv', $authProtocol, $authPassword, $privProtocol, $privPassword, '1.3.6.1.2.1.2.1.0', $timeout, $retries);
        if ($ifNumber !== false) {
            $snmpData['ifNumber'] = $ifNumber;
        }
        
        $response['success'] = true;
        $response['snmp_data'] = $snmpData;
        $response['message'] = 'SNMP v3 bağlantısı başarılı!';
        
    } else {
        throw new Exception('Geçersiz action');
    }
    
} catch (Exception $e) {
    $response['success'] = false;
    $response['error'] = $e->getMessage();
    $response['details'] = [
        'file' => $e->getFile(),
        'line' => $e->getLine(),
        'trace' => $e->getTraceAsString()
    ];
}

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
