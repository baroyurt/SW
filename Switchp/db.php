<?php
/**
 * Database Connection
 * Uses centralized configuration
 */

// Include configuration
require_once 'config.php';

// Error reporting
error_reporting(0); // Don't display errors on screen
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

// Start output buffering
ob_start();

// Get database configuration
$cfg = Config::get();

// Create database connection
$conn = new mysqli(
    $cfg['db_host'],
    $cfg['db_user'],
    $cfg['db_pass'],
    $cfg['db_name']
);

// Check connection
if ($conn->connect_error) {
    // Clear output and return JSON error
    ob_end_clean();
    header('Content-Type: application/json');
    error_log("Database connection failed: " . $conn->connect_error);
    die(json_encode([
        "success" => false,
        "error" => "Veritabanı bağlantısı başarısız. Lütfen sistem yöneticisi ile iletişime geçin."
    ]));
}

// Set charset
$conn->set_charset("utf8mb4");

// Check connection
if ($conn->connect_error) {
    // Clear output and return JSON error
    ob_end_clean();
    header('Content-Type: application/json');
    error_log("Database connection failed: " . $conn->connect_error);
    die(json_encode([
        "success" => false,
        "error" => "Veritabanı bağlantısı başarısız. Lütfen sistem yöneticisi ile iletişime geçin."
    ]));
}

// Set charset
$conn->set_charset("utf8mb4");

// Ensure logs directory exists
if (!file_exists(__DIR__ . '/logs')) {
    mkdir(__DIR__ . '/logs', 0755, true);
}

/**
 * Load SNMPv3 credentials for a given switch IP from config.yml.
 *
 * Used as a fallback when the snmp_devices table has no entry for a switch
 * (e.g. the Python SNMP worker has not yet run a successful poll for it).
 *
 * Returns an array with keys:
 *   ip_address, snmp_version, snmp_v3_username, snmp_v3_auth_protocol,
 *   snmp_v3_auth_password, snmp_v3_priv_protocol, snmp_v3_priv_password
 * or null if credentials cannot be found.
 *
 * @param string $switchIp  IP address from the switches table (s.ip)
 * @return array|null
 */
function getSnmpCredsFromConfig(string $switchIp): ?array {
    $cfgFile = __DIR__ . '/snmp_worker/config/config.yml';
    if (!$switchIp || !file_exists($cfgFile)) {
        return null;
    }

    $content = file_get_contents($cfgFile);
    $escapedIp = preg_quote($switchIp, '/');

    // Pattern 1: per-switch snmp_v3 block (preferred — switch may have unique credentials)
    //   - name: "SW31-RUBY"
    //     host: "172.18.1.218"
    //     ...
    //     snmp_v3:
    //       username: "snmpuser"
    //       auth_protocol: "SHA"
    //       auth_password: "AuthPass123!"
    //       priv_protocol: "AES"
    //       priv_password: "PrivPass123!"
    $perSwitchPattern =
        '/host:\s*"?' . $escapedIp . '"?.*?' .
        'snmp_v3:\s*\n\s+username:\s*"([^"]+)"\s+' .
        'auth_protocol:\s*"([^"]+)"\s+' .
        'auth_password:\s*"([^"]+)"\s+' .
        'priv_protocol:\s*"([^"]+)"\s+' .
        'priv_password:\s*"([^"]+)"/s';

    if (preg_match($perSwitchPattern, $content, $m)) {
        return [
            'ip_address'            => $switchIp,
            'snmp_version'          => '3',
            'snmp_v3_username'      => $m[1],
            'snmp_v3_auth_protocol' => $m[2],
            'snmp_v3_auth_password' => $m[3],
            'snmp_v3_priv_protocol' => $m[4],
            'snmp_v3_priv_password' => $m[5],
        ];
    }

    // Pattern 2: global snmp section (fallback — all switches share one credential set)
    //   snmp:
    //     version: "3"
    //     username: "snmpuser"
    //     auth_protocol: "SHA"
    //     auth_password: "AuthPass123"
    //     priv_protocol: "AES"
    //     priv_password: "PrivPass123"
    $globalPattern =
        '/snmp:\s+version:\s*"3"\s+' .
        'username:\s*"([^"]+)"\s+' .
        'auth_protocol:\s*"([^"]+)"\s+' .
        'auth_password:\s*"([^"]+)"\s+' .
        'priv_protocol:\s*"([^"]+)"\s+' .
        'priv_password:\s*"([^"]+)"/s';

    if (preg_match($globalPattern, $content, $m)) {
        return [
            'ip_address'            => $switchIp,
            'snmp_version'          => '3',
            'snmp_v3_username'      => $m[1],
            'snmp_v3_auth_protocol' => $m[2],
            'snmp_v3_auth_password' => $m[3],
            'snmp_v3_priv_protocol' => $m[4],
            'snmp_v3_priv_password' => $m[5],
        ];
    }

    return null;
}
?>