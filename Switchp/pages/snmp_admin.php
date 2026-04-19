<?php
session_start();
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

// Initialize auth
$auth = new Auth($conn);

// Check if user is authenticated
if (!$auth->isLoggedIn()) {
    header('Location: ../login.php');
    exit();
}

// Admin role required for SNMP administration
if (!$auth->isAdmin()) {
    header('Location: ../index.php?error=admin_required');
    exit();
}
function parseYamlConfig($filename) {
    if (!file_exists($filename)) {
        return null;
    }
    
    // Simple YAML parser (basic implementation)
    $content = file_get_contents($filename);
    $config = [];
    
    // Parse switches
    preg_match_all('/- name: "([^"]+)"\s+host: "([^"]+)"\s+vendor: "([^"]*)"\s+model: "([^"]*)"\s+enabled: (true|false)\s+description: "([^"]*)"/', $content, $matches, PREG_SET_ORDER);
    $config['switches'] = [];
    foreach ($matches as $match) {
        $sw = [
            'name' => $match[1],
            'host' => $match[2],
            'vendor' => $match[3],
            'model' => $match[4],
            'enabled' => $match[5] === 'true',
            'description' => $match[6]
        ];

        // Extract the YAML block belonging to this switch (up to the next switch or a top-level key)
        $escapedName = preg_quote($match[1], '/');
        if (preg_match('/- name: "' . $escapedName . '"(.*?)(?=\n  - name:|\n[a-z_]+:|\z)/s', $content, $swBlock)) {
            $block = $swBlock[0];

            // snmp_version
            if (preg_match('/snmp_version:\s+"([^"]+)"/', $block, $v)) {
                $sw['snmp_version'] = $v[1];
            }

            // snmp_v3 block — parse each field independently for robustness
            if (preg_match('/snmp_v3:/', $block)) {
                $v3 = [];
                if (preg_match('/username:\s+"([^"]*)"/', $block, $m))      $v3['username']      = $m[1];
                if (preg_match('/auth_protocol:\s+"([^"]*)"/', $block, $m)) $v3['auth_protocol'] = $m[1];
                if (preg_match('/auth_password:\s+"([^"]*)"/', $block, $m)) $v3['auth_password'] = $m[1];
                if (preg_match('/priv_protocol:\s+"([^"]*)"/', $block, $m)) $v3['priv_protocol'] = $m[1];
                if (preg_match('/priv_password:\s+"([^"]*)"/', $block, $m)) $v3['priv_password'] = $m[1];
                if (preg_match('/engine_id:\s+"([^"]+)"/', $block, $m))     $v3['engine_id']     = $m[1];
                if (!empty($v3)) {
                    $sw['snmp_v3'] = $v3;
                }
            }
        }

        $config['switches'][] = $sw;
    }
    
    // Parse database
    if (preg_match('/database:\s+host: ([^\s]+)\s+port: ([^\s]+)\s+name: ([^\s]+)\s+user: ([^\s]+)\s+password: "([^"]*)"/s', $content, $match)) {
        $config['database'] = [
            'host' => $match[1],
            'port' => $match[2],
            'name' => $match[3],
            'user' => $match[4],
            'password' => $match[5]
        ];
    }
    
    // Parse SNMP
    if (preg_match('/snmp:\s+version: "([^"]+)"\s+username: "([^"]+)"\s+auth_protocol: "([^"]+)"\s+auth_password: "([^"]+)"\s+priv_protocol: "([^"]+)"\s+priv_password: "([^"]+)"/s', $content, $match)) {
        $config['snmp'] = [
            'version' => $match[1],
            'username' => $match[2],
            'auth_protocol' => $match[3],
            'auth_password' => $match[4],
            'priv_protocol' => $match[5],
            'priv_password' => $match[6]
        ];
        // Preserve optional performance tuning fields (not shown in UI but present in config)
        if (preg_match('/^snmp:.*?timeout:\s+(\d+)/ms', $content, $tm))
            $config['snmp']['timeout'] = (int)$tm[1];
        if (preg_match('/^snmp:.*?retries:\s+(\d+)/ms', $content, $rm))
            $config['snmp']['retries'] = (int)$rm[1];
        if (preg_match('/^snmp:.*?max_bulk_size:\s+(\d+)/ms', $content, $bm))
            $config['snmp']['max_bulk_size'] = (int)$bm[1];
    }
    
    // Parse Telegram
    if (preg_match('/telegram:\s+enabled: (true|false)\s+bot_token: "([^"]+)"\s+chat_id: "([^"]+)"/s', $content, $match)) {
        $config['telegram'] = [
            'enabled' => $match[1] === 'true',
            'bot_token' => $match[2],
            'chat_id' => $match[3]
        ];
    }
    
    // Parse Email
    if (preg_match('/email:\s+enabled: (true|false)\s+smtp_host: "([^"]*)"\s+smtp_port: ([^\s]+)\s+smtp_user: "([^"]*)"\s+smtp_password: "([^"]*)"\s+from_address: "([^"]*)"/s', $content, $match)) {
        $config['email'] = [
            'enabled' => $match[1] === 'true',
            'smtp_host' => $match[2],
            'smtp_port' => $match[3],
            'smtp_user' => $match[4],
            'smtp_password' => $match[5],
            'from_address' => $match[6]
        ];
        // Parse to_addresses — extract only items inside the to_addresses block
        $toAddresses = [];
        if (preg_match('/to_addresses:\s*(.*?)(?=\n\s*[a-z_]+:|\Z)/s', $content, $taBlock)) {
            preg_match_all('/^\s+- "([^"]+)"/m', $taBlock[1], $taMatches);
            $toAddresses = $taMatches[1] ?? [];
        }
        $config['email']['to_addresses'] = $toAddresses;
    }
    
    return $config;
}

function buildSwitchesYaml($config) {
    $globalVersion = ltrim($config['snmp']['version'] ?? '3', 'v');
    $yaml = "switches:\n";
    foreach ($config['switches'] as $switch) {
        $yaml .= "  - name: \"" . $switch['name'] . "\"\n";
        $yaml .= "    host: \"" . $switch['host'] . "\"\n";
        $yaml .= "    vendor: \"" . $switch['vendor'] . "\"\n";
        $yaml .= "    model: \"" . $switch['model'] . "\"\n";
        $yaml .= "    enabled: " . ($switch['enabled'] ? 'true' : 'false') . "\n";
        $yaml .= "    description: \"" . $switch['description'] . "\"\n";
        if (!empty($switch['snmp_v3'])) {
            // Use stored per-switch version; fall back to global config version (strip leading 'v' if present)
            $snmpVersion = $switch['snmp_version'] ?? $globalVersion;
            $v3 = $switch['snmp_v3'];
            $yaml .= "    snmp_version: \"" . $snmpVersion . "\"\n";
            $yaml .= "    snmp_v3:\n";
            $yaml .= "      username: \"" . ($v3['username'] ?? '') . "\"\n";
            $yaml .= "      auth_protocol: \"" . ($v3['auth_protocol'] ?? 'SHA') . "\"\n";
            $yaml .= "      auth_password: \"" . ($v3['auth_password'] ?? '') . "\"\n";
            $yaml .= "      priv_protocol: \"" . ($v3['priv_protocol'] ?? 'AES') . "\"\n";
            $yaml .= "      priv_password: \"" . ($v3['priv_password'] ?? '') . "\"\n";
            if (!empty($v3['engine_id'])) {
                $yaml .= "      engine_id: \"" . $v3['engine_id'] . "\"\n";
            }
        }
        $yaml .= "\n";
    }
    return $yaml;
}

/**
 * Replace a top-level YAML section in $content with $newBlock.
 * Returns the updated content, or null on error.
 */
function replaceSectionInYaml($content, $sectionName, $newBlock) {
    return preg_replace(
        '/^' . preg_quote($sectionName, '/') . ':.*?(?=^[a-z_]+:|\Z)/ms',
        $newBlock,
        $content
    );
}

function saveYamlConfig($filename, $config) {
    // Read existing file to preserve all settings not managed here
    $existingContent = file_exists($filename) ? file_get_contents($filename) : '';

    if ($existingContent !== '') {
        $updated = $existingContent;

        // Update the switches: block
        $newSwitchesBlock = buildSwitchesYaml($config);
        $tmp = replaceSectionInYaml($updated, 'switches', $newSwitchesBlock);
        if ($tmp !== null) {
            // If section not found, append it
            $updated = ($tmp !== $updated) ? $tmp : rtrim($updated) . "\n\n" . $newSwitchesBlock;
        }

        // Update the snmp: block if present in config
        if (!empty($config['snmp'])) {
            $snmp = $config['snmp'];
            $snmpBlock = "snmp:\n";
            $snmpBlock .= "  version: \"" . ($snmp['version'] ?? '3') . "\"\n";
            $snmpBlock .= "  username: \"" . ($snmp['username'] ?? '') . "\"\n";
            $snmpBlock .= "  auth_protocol: \"" . ($snmp['auth_protocol'] ?? 'SHA') . "\"\n";
            $snmpBlock .= "  auth_password: \"" . ($snmp['auth_password'] ?? '') . "\"\n";
            $snmpBlock .= "  priv_protocol: \"" . ($snmp['priv_protocol'] ?? 'AES') . "\"\n";
            $snmpBlock .= "  priv_password: \"" . ($snmp['priv_password'] ?? '') . "\"\n";
            // Preserve performance tuning fields if present (parsed from existing config)
            if (isset($snmp['timeout']))       $snmpBlock .= "  timeout: " . (int)$snmp['timeout'] . "\n";
            if (isset($snmp['retries']))       $snmpBlock .= "  retries: " . (int)$snmp['retries'] . "\n";
            if (isset($snmp['max_bulk_size'])) $snmpBlock .= "  max_bulk_size: " . (int)$snmp['max_bulk_size'] . "\n";
            $tmp = replaceSectionInYaml($updated, 'snmp', $snmpBlock);
            if ($tmp !== null && $tmp !== $updated) {
                $updated = $tmp;
            }
        }

        // Update the telegram: block if present in config
        if (!empty($config['telegram'])) {
            $tg = $config['telegram'];
            $tgBlock = "telegram:\n";
            $tgBlock .= "  enabled: " . (($tg['enabled'] ?? false) ? 'true' : 'false') . "\n";
            $tgBlock .= "  bot_token: \"" . ($tg['bot_token'] ?? '') . "\"\n";
            $tgBlock .= "  chat_id: \"" . ($tg['chat_id'] ?? '') . "\"\n";
            $tmp = replaceSectionInYaml($updated, 'telegram', $tgBlock);
            if ($tmp !== null && $tmp !== $updated) {
                $updated = $tmp;
            }
        }

        // Update the email: block if present in config
        if (!empty($config['email'])) {
            $em = $config['email'];
            $toAddresses = $em['to_addresses'] ?? [];
            $emBlock = "email:\n";
            $emBlock .= "  enabled: " . (($em['enabled'] ?? false) ? 'true' : 'false') . "\n";
            $emBlock .= "  smtp_host: \"" . ($em['smtp_host'] ?? '') . "\"\n";
            $emBlock .= "  smtp_port: " . ($em['smtp_port'] ?? 465) . "\n";
            $emBlock .= "  smtp_user: \"" . ($em['smtp_user'] ?? '') . "\"\n";
            $emBlock .= "  smtp_password: \"" . ($em['smtp_password'] ?? '') . "\"\n";
            $emBlock .= "  from_address: \"" . ($em['from_address'] ?? '') . "\"\n";
            if (empty($toAddresses)) {
                $emBlock .= "  to_addresses: []\n";
            } else {
                $emBlock .= "  to_addresses:\n";
                foreach ($toAddresses as $emailAddr) {
                    $emBlock .= "    - \"" . $emailAddr . "\"\n";
                }
            }
            $emBlock .= "  notify_on:\n";
            $emBlock .= "    - port_down\n";
            $emBlock .= "    - device_unreachable\n";
            $tmp = replaceSectionInYaml($updated, 'email', $emBlock);
            if ($tmp !== null && $tmp !== $updated) {
                $updated = $tmp;
            }
        }

        // Write atomically: temp file then rename
        $tmpFile = $filename . '.tmp';
        if (file_put_contents($tmpFile, $updated, LOCK_EX) !== false) {
            return rename($tmpFile, $filename);
        }
        @unlink($tmpFile);
        return false;
    }

    // Fallback: generate a complete config from scratch (only when file doesn't exist yet)
    $yaml = "# SNMP Worker Configuration\n";
    $yaml .= "# Active configuration file for SNMP monitoring\n\n";
    $yaml .= "# Database Configuration\n";
    $yaml .= "database:\n";
    $yaml .= "  host: " . ($config['database']['host'] ?? '127.0.0.1') . "\n";
    $yaml .= "  port: " . ($config['database']['port'] ?? '3306') . "\n";
    $yaml .= "  name: " . ($config['database']['name'] ?? 'switchdb') . "\n";
    $yaml .= "  user: " . ($config['database']['user'] ?? 'root') . "\n";
    $yaml .= "  password: \"" . ($config['database']['password'] ?? '') . "\"\n";
    $yaml .= "  pool_size: 10\n";
    $yaml .= "  max_overflow: 20\n\n";
    $yaml .= "# Global SNMP Configuration\n";
    $yaml .= "snmp:\n";
    $yaml .= "  version: \"" . ($config['snmp']['version'] ?? '3') . "\"\n";
    $yaml .= "  username: \"" . ($config['snmp']['username'] ?? 'snmpuser') . "\"\n";
    $yaml .= "  auth_protocol: \"" . ($config['snmp']['auth_protocol'] ?? 'SHA') . "\"\n";
    $yaml .= "  auth_password: \"" . ($config['snmp']['auth_password'] ?? '') . "\"\n";
    $yaml .= "  priv_protocol: \"" . ($config['snmp']['priv_protocol'] ?? 'AES') . "\"\n";
    $yaml .= "  priv_password: \"" . ($config['snmp']['priv_password'] ?? '') . "\"\n";
    $yaml .= "  timeout: 2\n";
    $yaml .= "  retries: 1\n";
    $yaml .= "  max_bulk_size: 50\n\n";
    $yaml .= "# Polling Configuration\n";
    $yaml .= "polling:\n";
    $yaml .= "  interval: 30\n";
    $yaml .= "  parallel_devices: 5\n";
    $yaml .= "  max_workers: 10\n\n";
    $yaml .= buildSwitchesYaml($config);
    $yaml .= "# Alarm Configuration\n";
    $yaml .= "alarms:\n";
    $yaml .= "  enabled: true\n";
    $yaml .= "  debounce_time: 60\n";
    $yaml .= "  unreachable_threshold: 3\n";
    $yaml .= "  trigger_on:\n";
    $yaml .= "    - port_down\n";
    $yaml .= "    - device_unreachable\n";
    $yaml .= "    - snmp_error\n";
    $yaml .= "    - mac_moved\n";
    $yaml .= "    - vlan_changed\n";
    $yaml .= "    - description_changed\n\n";
    $yaml .= "# Telegram Notifications\n";
    $yaml .= "telegram:\n";
    $yaml .= "  enabled: " . (($config['telegram']['enabled'] ?? false) ? 'true' : 'false') . "\n";
    $yaml .= "  bot_token: \"" . ($config['telegram']['bot_token'] ?? '') . "\"\n";
    $yaml .= "  chat_id: \"" . ($config['telegram']['chat_id'] ?? '') . "\"\n";
    $yaml .= "  notify_on:\n";
    $yaml .= "    - port_down\n";
    $yaml .= "    - port_up\n";
    $yaml .= "    - device_unreachable\n\n";
    $em = $config['email'] ?? [];
    $toAddresses = $em['to_addresses'] ?? [];
    $yaml .= "# Email Notifications\n";
    $yaml .= "email:\n";
    $yaml .= "  enabled: " . (($em['enabled'] ?? false) ? 'true' : 'false') . "\n";
    $yaml .= "  smtp_host: \"" . ($em['smtp_host'] ?? 'smtp.yandex.com') . "\"\n";
    $yaml .= "  smtp_port: " . ($em['smtp_port'] ?? 465) . "\n";
    $yaml .= "  smtp_user: \"" . ($em['smtp_user'] ?? '') . "\"\n";
    $yaml .= "  smtp_password: \"" . ($em['smtp_password'] ?? '') . "\"\n";
    $yaml .= "  from_address: \"" . ($em['from_address'] ?? '') . "\"\n";
    if (empty($toAddresses)) {
        $yaml .= "  to_addresses: []\n";
    } else {
        $yaml .= "  to_addresses:\n";
        foreach ($toAddresses as $emailAddr) {
            $yaml .= "    - \"" . $emailAddr . "\"\n";
        }
    }
    $yaml .= "  notify_on:\n";
    $yaml .= "    - port_down\n";
    $yaml .= "    - device_unreachable\n\n";

    $tmpFile = $filename . '.tmp';
    if (file_put_contents($tmpFile, $yaml, LOCK_EX) !== false) {
        return rename($tmpFile, $filename);
    }
    @unlink($tmpFile);
    return false;
}

// Config file path
$configPath = __DIR__ . '/../snmp_worker/config/config.yml';

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    // Load config - some actions don't require it
    $config = parseYamlConfig($configPath);
    
    // Actions that require config file
    $requiresConfig = ['add_switch', 'update_switch', 'delete_switch', 'update_telegram', 
                       'update_email', 'add_email', 'remove_email', 'update_snmp', 'restart_service'];
    
    if (in_array($_POST['action'], $requiresConfig) && !$config) {
        echo json_encode(['success' => false, 'error' => 'Config dosyası okunamadı']);
        exit();
    }
    
    switch ($_POST['action']) {
        case 'add_switch':
            $newSwitch = [
                'name' => $_POST['name'],
                'host' => $_POST['host'],
                'vendor' => $_POST['vendor'] ?? 'cisco',
                'model' => $_POST['model'] ?? '',
                'enabled' => isset($_POST['enabled']) && $_POST['enabled'] === 'true',
                'description' => $_POST['description'] ?? ''
            ];
            // Inherit global SNMPv3 credentials so the worker can reach the new device
            if (!empty($config['snmp']) && in_array($config['snmp']['version'] ?? '', ['3', 'v3'])) {
                $newSwitch['snmp_version'] = '3';
                $newSwitch['snmp_v3'] = [
                    'username'      => $config['snmp']['username'] ?? '',
                    'auth_protocol' => $config['snmp']['auth_protocol'] ?? 'SHA',
                    'auth_password' => $config['snmp']['auth_password'] ?? '',
                    'priv_protocol' => $config['snmp']['priv_protocol'] ?? 'AES',
                    'priv_password' => $config['snmp']['priv_password'] ?? ''
                ];
                // Allow setting per-switch engine_id (required for CBS350)
                $engineId = trim($_POST['engine_id'] ?? '');
                if ($engineId !== '') {
                    $newSwitch['snmp_v3']['engine_id'] = $engineId;
                }
            }
            $config['switches'][] = $newSwitch;
            saveYamlConfig($configPath, $config);
            echo json_encode(['success' => true, 'message' => 'Switch başarıyla eklendi']);
            break;
            
        case 'update_switch':
            $index = (int)$_POST['index'];
            if (isset($config['switches'][$index])) {
                // Preserve existing snmp_v3 / snmp_version so they are not lost on save
                $existingSnmpV3      = $config['switches'][$index]['snmp_v3'] ?? null;
                $existingSnmpVersion = $config['switches'][$index]['snmp_version'] ?? null;
                // Allow updating engine_id from the form
                if ($existingSnmpV3 !== null) {
                    $engineId = trim($_POST['engine_id'] ?? '');
                    if ($engineId !== '') {
                        $existingSnmpV3['engine_id'] = $engineId;
                    } elseif (isset($existingSnmpV3['engine_id'])) {
                        unset($existingSnmpV3['engine_id']);
                    }
                }
                $config['switches'][$index] = [
                    'name'         => $_POST['name'],
                    'host'         => $_POST['host'],
                    'vendor'       => $_POST['vendor'] ?? 'cisco',
                    'model'        => $_POST['model'] ?? '',
                    'enabled'      => isset($_POST['enabled']) && $_POST['enabled'] === 'true',
                    'description'  => $_POST['description'] ?? '',
                    'snmp_version' => $existingSnmpVersion,
                    'snmp_v3'      => $existingSnmpV3
                ];
                saveYamlConfig($configPath, $config);
                echo json_encode(['success' => true, 'message' => 'Switch başarıyla güncellendi']);
            } else {
                echo json_encode(['success' => false, 'error' => 'Switch bulunamadı']);
            }
            break;
            
        case 'delete_switch':
            $index = (int)$_POST['index'];
            if (isset($config['switches'][$index])) {
                array_splice($config['switches'], $index, 1);
                saveYamlConfig($configPath, $config);
                echo json_encode(['success' => true, 'message' => 'Switch başarıyla silindi']);
            } else {
                echo json_encode(['success' => false, 'error' => 'Switch bulunamadı']);
            }
            break;
            
        case 'update_telegram':
            $config['telegram'] = [
                'enabled' => isset($_POST['enabled']) && $_POST['enabled'] === 'true',
                'bot_token' => $_POST['bot_token'],
                'chat_id' => $_POST['chat_id']
            ];
            saveYamlConfig($configPath, $config);
            echo json_encode(['success' => true, 'message' => 'Telegram ayarları güncellendi']);
            break;
            
        case 'update_email':
            $to_addresses = [];
            if (isset($_POST['to_addresses']) && is_array($_POST['to_addresses'])) {
                $to_addresses = array_filter($_POST['to_addresses'], function($email) {
                    return filter_var($email, FILTER_VALIDATE_EMAIL);
                });
            }
            
            $config['email'] = [
                'enabled' => isset($_POST['enabled']) && $_POST['enabled'] === 'true',
                'smtp_host' => $_POST['smtp_host'],
                'smtp_port' => (int)$_POST['smtp_port'],
                'smtp_user' => $_POST['smtp_user'],
                'smtp_password' => $_POST['smtp_password'],
                'from_address' => $_POST['from_address'],
                'to_addresses' => $to_addresses
            ];
            saveYamlConfig($configPath, $config);
            echo json_encode(['success' => true, 'message' => 'Email ayarları güncellendi']);
            break;
            
        case 'update_snmp':
            $config['snmp'] = [
                'version' => $_POST['version'],
                'username' => $_POST['username'],
                'auth_protocol' => $_POST['auth_protocol'],
                'auth_password' => $_POST['auth_password'],
                'priv_protocol' => $_POST['priv_protocol'],
                'priv_password' => $_POST['priv_password']
            ];
            saveYamlConfig($configPath, $config);
            echo json_encode(['success' => true, 'message' => 'SNMP ayarları güncellendi']);
            break;
            
        case 'get_config':
            echo json_encode(['success' => true, 'config' => $config]);
            break;
            
        case 'get_alarm_severities':
            // Get alarm severity configuration from database
            try {
                $stmt = $conn->prepare("SELECT alarm_type, severity, telegram_enabled, email_enabled, description FROM alarm_severity_config ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, alarm_type");
                $stmt->execute();
                $result = $stmt->get_result();
                $severities = $result->fetch_all(MYSQLI_ASSOC);
                foreach ($severities as &$row) {
                    $row['telegram_enabled'] = (int)$row['telegram_enabled'];
                    $row['email_enabled']    = (int)$row['email_enabled'];
                }
                unset($row);
                echo json_encode(['success' => true, 'severities' => $severities]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => 'Veritabanı hatası: ' . $e->getMessage()]);
            }
            break;
            
        case 'update_alarm_severity':
            // Update alarm severity configuration
            try {
                $alarm_type = $_POST['alarm_type'];
                $severity = $_POST['severity'];
                $telegram_enabled = isset($_POST['telegram_enabled']) && $_POST['telegram_enabled'] === 'true' ? 1 : 0;
                $email_enabled = isset($_POST['email_enabled']) && $_POST['email_enabled'] === 'true' ? 1 : 0;
                
                // Validate severity
                $valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
                if (!in_array($severity, $valid_severities)) {
                    echo json_encode(['success' => false, 'error' => 'Geçersiz severity seviyesi']);
                    break;
                }
                
                $stmt = $conn->prepare("UPDATE alarm_severity_config SET severity = ?, telegram_enabled = ?, email_enabled = ? WHERE alarm_type = ?");
                $stmt->bind_param("siis", $severity, $telegram_enabled, $email_enabled, $alarm_type);
                
                if ($stmt->execute()) {
                    echo json_encode(['success' => true, 'message' => 'Alarm seviyesi güncellendi']);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Güncelleme başarısız: ' . $conn->error]);
                }
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => 'Hata: ' . $e->getMessage()]);
            }
            break;
            
        case 'test_telegram':
            // Test Telegram notification (server-side)
            try {
                $token = $_POST['bot_token'] ?? '';
                $chat_id = $_POST['chat_id'] ?? '';
                
                if (empty($token) || empty($chat_id)) {
                    echo json_encode(['success' => false, 'error' => 'Bot Token ve Chat ID gerekli']);
                    break;
                }
                
                $message = "🧪 Test Mesajı\n\n" .
                          "✅ Telegram entegrasyonu çalışıyor!\n" .
                          "⏰ " . date('d.m.Y H:i:s') . "\n\n" .
                          "Bu bir test mesajıdır. SNMP alarm sisteminiz doğru şekilde yapılandırılmış.";
                
                $url = "https://api.telegram.org/bot{$token}/sendMessage";
                $postData = [
                    'chat_id' => $chat_id,
                    'text' => $message,
                    'parse_mode' => 'HTML'
                ];
                
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($postData));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
                curl_setopt($ch, CURLOPT_TIMEOUT, 10);
                
                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curlError = curl_error($ch);
                curl_close($ch);
                
                if ($curlError) {
                    echo json_encode(['success' => false, 'error' => 'Bağlantı hatası: ' . $curlError]);
                    break;
                }
                
                $result = json_decode($response, true);
                
                if ($httpCode === 200 && isset($result['ok']) && $result['ok']) {
                    echo json_encode(['success' => true, 'message' => 'Test mesajı başarıyla gönderildi! Telegram\'ınızı kontrol edin.']);
                } else {
                    $errorMsg = $result['description'] ?? 'Bilinmeyen hata';
                    echo json_encode(['success' => false, 'error' => 'Telegram API hatası: ' . $errorMsg]);
                }
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => 'Hata: ' . $e->getMessage()]);
            }
            break;
            
        case 'get_db_switches':
            // Get switches from database
            try {
                // Check if vendor column exists
                $checkVendor = $conn->query("SHOW COLUMNS FROM switches LIKE 'vendor'");
                $hasVendor = $checkVendor && $checkVendor->num_rows > 0;
                
                // Check if description column exists
                $checkDesc = $conn->query("SHOW COLUMNS FROM switches LIKE 'description'");
                $hasDescription = $checkDesc && $checkDesc->num_rows > 0;
                
                // Build query based on available columns
                $vendorCol = $hasVendor ? 'vendor' : 'brand as vendor';
                $descCol = $hasDescription ? 'description' : 'NULL as description';
                
                $stmt = $conn->prepare("SELECT id, name, ip, $vendorCol, model, $descCol, ports FROM switches ORDER BY name");
                if (!$stmt) {
                    throw new Exception("Prepare failed: " . $conn->error);
                }
                $stmt->execute();
                $result = $stmt->get_result();
                if (!$result) {
                    throw new Exception("Get result failed: " . $stmt->error);
                }
                $dbSwitches = $result->fetch_all(MYSQLI_ASSOC);
                
                // Check which switches are already in SNMP config
                $configSwitchIPs = [];
                if ($config && isset($config['switches']) && is_array($config['switches'])) {
                    $configSwitchIPs = array_column($config['switches'], 'host');
                }
                
                foreach ($dbSwitches as &$sw) {
                    $sw['in_snmp_config'] = in_array($sw['ip'], $configSwitchIPs);
                }
                
                echo json_encode(['success' => true, 'switches' => $dbSwitches]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => 'Veritabanı hatası: ' . $e->getMessage()]);
            }
            break;
            
        case 'import_from_db':
            // Import switch from database to SNMP config
            try {
                $switchId = (int)$_POST['switch_id'];
                
                // Check if vendor column exists
                $checkVendor = $conn->query("SHOW COLUMNS FROM switches LIKE 'vendor'");
                $hasVendor = $checkVendor && $checkVendor->num_rows > 0;
                
                // Check if description column exists
                $checkDesc = $conn->query("SHOW COLUMNS FROM switches LIKE 'description'");
                $hasDescription = $checkDesc && $checkDesc->num_rows > 0;
                
                // Build query based on available columns
                $vendorCol = $hasVendor ? 'vendor' : 'brand as vendor';
                $descCol = $hasDescription ? 'description' : 'NULL as description';
                
                $stmt = $conn->prepare("SELECT id, name, ip, $vendorCol, model, $descCol FROM switches WHERE id = ?");
                if (!$stmt) {
                    throw new Exception("Prepare failed: " . $conn->error);
                }
                $stmt->bind_param("i", $switchId);
                $stmt->execute();
                $result = $stmt->get_result();
                if (!$result) {
                    throw new Exception("Get result failed: " . $stmt->error);
                }
                $dbSwitch = $result->fetch_assoc();
                
                if (!$dbSwitch) {
                    echo json_encode(['success' => false, 'error' => 'Switch veritabanında bulunamadı']);
                    break;
                }
                
                // Check if already exists in config
                $exists = false;
                foreach ($config['switches'] as $sw) {
                    if ($sw['host'] === $dbSwitch['ip']) {
                        $exists = true;
                        break;
                    }
                }
                
                if ($exists) {
                    echo json_encode(['success' => false, 'error' => 'Bu switch zaten SNMP yapılandırmasında mevcut']);
                    break;
                }
                
                // Add to config
                $importedSwitch = [
                    'name' => $dbSwitch['name'],
                    'host' => $dbSwitch['ip'],
                    'vendor' => $dbSwitch['vendor'] ?: 'cisco',
                    'model' => $dbSwitch['model'] ?: '',
                    'enabled' => true,
                    'description' => $dbSwitch['description'] ?: ''
                ];
                // Inherit global SNMPv3 credentials so the worker can reach the imported device
                if (!empty($config['snmp']) && in_array($config['snmp']['version'] ?? '', ['3', 'v3'])) {
                    $importedSwitch['snmp_version'] = '3';
                    $importedSwitch['snmp_v3'] = [
                        'username'      => $config['snmp']['username'] ?? '',
                        'auth_protocol' => $config['snmp']['auth_protocol'] ?? 'SHA',
                        'auth_password' => $config['snmp']['auth_password'] ?? '',
                        'priv_protocol' => $config['snmp']['priv_protocol'] ?? 'AES',
                        'priv_password' => $config['snmp']['priv_password'] ?? ''
                    ];
                }
                $config['switches'][] = $importedSwitch;
                
                saveYamlConfig($configPath, $config);
                echo json_encode(['success' => true, 'message' => 'Switch SNMP yapılandırmasına eklendi']);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => 'Hata: ' . $e->getMessage()]);
            }
            break;
            
        case 'import_all_from_db':
            // Import all database switches that aren't in SNMP config yet
            try {
                // Check if vendor column exists
                $checkVendor = $conn->query("SHOW COLUMNS FROM switches LIKE 'vendor'");
                $hasVendor = $checkVendor && $checkVendor->num_rows > 0;
                
                // Check if description column exists
                $checkDesc = $conn->query("SHOW COLUMNS FROM switches LIKE 'description'");
                $hasDescription = $checkDesc && $checkDesc->num_rows > 0;
                
                // Build query based on available columns
                $vendorCol = $hasVendor ? 'vendor' : 'brand as vendor';
                $descCol = $hasDescription ? 'description' : 'NULL as description';
                
                $stmt = $conn->prepare("SELECT id, name, ip, $vendorCol, model, $descCol FROM switches WHERE ip IS NOT NULL AND ip != '' ORDER BY name");
                if (!$stmt) {
                    throw new Exception("Prepare failed: " . $conn->error);
                }
                $stmt->execute();
                $result = $stmt->get_result();
                if (!$result) {
                    throw new Exception("Get result failed: " . $stmt->error);
                }
                $dbSwitches = $result->fetch_all(MYSQLI_ASSOC);
                
                $configSwitchIPs = [];
                if ($config && isset($config['switches']) && is_array($config['switches'])) {
                    $configSwitchIPs = array_column($config['switches'], 'host');
                }
                $addedCount = 0;
                
                foreach ($dbSwitches as $dbSwitch) {
                    if (!in_array($dbSwitch['ip'], $configSwitchIPs)) {
                        $bulkSwitch = [
                            'name' => $dbSwitch['name'],
                            'host' => $dbSwitch['ip'],
                            'vendor' => $dbSwitch['vendor'] ?: 'cisco',
                            'model' => $dbSwitch['model'] ?: '',
                            'enabled' => true,
                            'description' => $dbSwitch['description'] ?: ''
                        ];
                        // Inherit global SNMPv3 credentials
                        if (!empty($config['snmp']) && in_array($config['snmp']['version'] ?? '', ['3', 'v3'])) {
                            $bulkSwitch['snmp_version'] = '3';
                            $bulkSwitch['snmp_v3'] = [
                                'username'      => $config['snmp']['username'] ?? '',
                                'auth_protocol' => $config['snmp']['auth_protocol'] ?? 'SHA',
                                'auth_password' => $config['snmp']['auth_password'] ?? '',
                                'priv_protocol' => $config['snmp']['priv_protocol'] ?? 'AES',
                                'priv_password' => $config['snmp']['priv_password'] ?? ''
                            ];
                        }
                        $config['switches'][] = $bulkSwitch;
                        $addedCount++;
                    }
                }
                
                if ($addedCount > 0) {
                    saveYamlConfig($configPath, $config);
                    echo json_encode(['success' => true, 'message' => "$addedCount switch SNMP yapılandırmasına eklendi"]);
                } else {
                    echo json_encode(['success' => true, 'message' => 'Eklenecek yeni switch bulunamadı']);
                }
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => 'Hata: ' . $e->getMessage()]);
            }
            break;
            
        case 'import_snmp_to_db':
            // Import all switches from the SNMP YAML config into the switches DB table.
            // Switches already present (matched by IP or name) are skipped.
            try {
                if (!$config || empty($config['switches'])) {
                    echo json_encode(['success' => false, 'error' => 'SNMP yapılandırmasında switch bulunamadı']);
                    break;
                }

                // Fetch existing switches from DB keyed by IP and name for duplicate detection
                $existingIPs   = [];
                $existingNames = [];
                $existingResult = $conn->query("SELECT name, ip FROM switches");
                if ($existingResult) {
                    while ($row = $existingResult->fetch_assoc()) {
                        if ($row['ip'])   $existingIPs[trim($row['ip'])]     = true;
                        if ($row['name']) $existingNames[trim($row['name'])] = true;
                    }
                }

                $addedCount   = 0;
                $skippedCount = 0;
                $errors       = [];

                foreach ($config['switches'] as $sw) {
                    $swName = trim($sw['name'] ?? '');
                    $swIP   = trim($sw['host'] ?? '');

                    if ($swName === '') {
                        $skippedCount++;
                        continue;
                    }

                    // Skip duplicates
                    if (($swIP !== '' && isset($existingIPs[$swIP])) || isset($existingNames[$swName])) {
                        $skippedCount++;
                        continue;
                    }

                    $brand  = $sw['vendor'] ?? null;
                    $model  = $sw['model']  ?? null;
                    $ipVal  = $swIP !== '' ? $swIP : null;

                    $stmt = $conn->prepare(
                        "INSERT INTO switches (name, brand, model, ports, status, ip) VALUES (?, ?, ?, 24, 'active', ?)"
                    );
                    if (!$stmt) {
                        $errors[] = "Prepare failed for '{$swName}': " . $conn->error;
                        continue;
                    }
                    $stmt->bind_param('ssss', $swName, $brand, $model, $ipVal);
                    if ($stmt->execute()) {
                        $addedCount++;
                        if ($ipVal !== null) $existingIPs[$ipVal]   = true;
                        $existingNames[$swName] = true;
                    } else {
                        $errors[] = "'{$swName}' eklenemedi: " . $stmt->error;
                    }
                    $stmt->close();
                }

                $msg = "{$addedCount} switch veritabanına eklendi";
                if ($skippedCount > 0) $msg .= ", {$skippedCount} zaten mevcut (atlandı)";
                if (!empty($errors))   $msg .= ". Hatalar: " . implode('; ', $errors);

                echo json_encode(['success' => true, 'message' => $msg, 'added' => $addedCount]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => 'Hata: ' . $e->getMessage()]);
            }
            break;

        default:
            echo json_encode(['success' => false, 'error' => 'Bilinmeyen işlem']);
    }
    exit();
}

// Load config for display
$config = parseYamlConfig($configPath);

// Ensure $config is never null to prevent JSON parse errors
if (!$config) {
    $config = [
        'switches' => [],
        'database' => [
            'host' => '127.0.0.1',
            'port' => '3306',
            'name' => 'switchdb',
            'user' => 'root',
            'password' => ''
        ],
        'snmp' => [
            'version' => 'v3',
            'username' => 'snmpuser',
            'auth_protocol' => 'SHA',
            'auth_password' => '',
            'priv_protocol' => 'AES',
            'priv_password' => ''
        ],
        'telegram' => [
            'enabled' => false,
            'bot_token' => '',
            'chat_id' => ''
        ],
        'email' => [
            'enabled' => false,
            'smtp_host' => '',
            'smtp_port' => '465',
            'smtp_user' => '',
            'smtp_password' => '',
            'from_address' => '',
            'to_addresses' => []
        ]
    ];
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SNMP Yönetim Paneli</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        :root {
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #0f172a;
            --dark-light: #1e293b;
            --text: #e2e8f0;
            --text-light: #94a3b8;
            --border: #334155;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.8) 100%);
            backdrop-filter: blur(10px);
            padding: 20px 30px;
            border-radius: 15px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            border: 1px solid rgba(56, 189, 248, 0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            color: var(--text);
            font-size: 28px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .header h1 i {
            color: var(--primary);
        }
        
        .header .actions {
            display: flex;
            gap: 10px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s;
            text-decoration: none;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success) 0%, #059669 100%);
            color: white;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }
        
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%);
            color: white;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        }
        
        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
        }
        
        .btn-secondary {
            background: rgba(30, 41, 59, 0.8);
            color: var(--text);
            border: 1px solid var(--border);
        }
        
        .btn-secondary:hover {
            background: rgba(30, 41, 59, 1);
            border-color: var(--primary);
        }
        
        .tabs {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.8) 100%);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            border: 1px solid rgba(56, 189, 248, 0.3);
            overflow: hidden;
        }
        
        .tab-header {
            display: flex;
            background: rgba(15, 23, 42, 0.6);
            border-bottom: 2px solid var(--border);
        }
        
        .tab-button {
            flex: 1;
            padding: 15px 20px;
            border: none;
            background: transparent;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            color: var(--text-light);
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .tab-button.active {
            color: var(--text);
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            border-bottom: 3px solid var(--primary);
            box-shadow: 0 5px 20px rgba(59, 130, 246, 0.4);
        }
        
        .tab-button:hover {
            background: rgba(56, 189, 248, 0.1);
            color: var(--text);
        }
        
        .tab-content {
            display: none;
            padding: 30px;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .card {
            background: rgba(30, 41, 59, 0.6);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid rgba(56, 189, 248, 0.2);
            transition: all 0.3s ease;
        }
        
        .card:hover {
            border-color: rgba(56, 189, 248, 0.4);
            box-shadow: 0 5px 20px rgba(56, 189, 248, 0.2);
        }
        
        .card h3 {
            color: var(--text);
            margin-bottom: 15px;
            font-size: 18px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card h3 i {
            color: var(--primary);
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-light);
            font-weight: 500;
            font-size: 14px;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px;
            background: rgba(15, 23, 42, 0.8);
            border: 2px solid rgba(56, 189, 248, 0.3);
            border-radius: 8px;
            font-size: 14px;
            color: var(--text);
            transition: all 0.3s ease;
        }
        
        .form-group input::placeholder,
        .form-group textarea::placeholder {
            color: var(--text-light);
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 20px rgba(56, 189, 248, 0.3);
            background: rgba(15, 23, 42, 0.9);
        }
        
        .form-group select {
            cursor: pointer;
        }
        
        .form-group select option {
            background: var(--dark);
            color: var(--text);
        }
        
        .switch-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
        }
        
        .switch-card {
            background: rgba(15, 23, 42, 0.8);
            border-radius: 12px;
            padding: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            border: 1px solid rgba(56, 189, 248, 0.2);
            transition: all 0.3s ease;
        }
        
        .switch-card:hover {
            transform: translateY(-3px);
            border-color: var(--primary);
            box-shadow: 0 8px 25px rgba(56, 189, 248, 0.3);
        }
        
        .switch-card h4 {
            color: var(--text);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .switch-card h4 i {
            color: var(--primary);
        }
        
        .switch-card p {
            color: var(--text-light);
            font-size: 14px;
            margin-bottom: 5px;
        }
        
        .switch-card p strong {
            color: var(--text);
        }
        
        .switch-card .actions {
            margin-top: 10px;
            display: flex;
            gap: 5px;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            backdrop-filter: blur(5px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        
        .modal.active {
            display: flex;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .modal-content {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.95) 100%);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            max-width: 500px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            border: 1px solid rgba(56, 189, 248, 0.3);
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            animation: slideUp 0.3s ease;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .modal-content h2 {
            color: var(--text);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .modal-content h2 i {
            color: var(--primary);
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
        }
        
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .status-badge.enabled {
            background: linear-gradient(135deg, var(--success) 0%, #059669 100%);
            color: white;
            box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
        }
        
        .status-badge.disabled {
            background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%);
            color: white;
            box-shadow: 0 2px 8px rgba(239, 68, 68, 0.3);
        }
        
        .email-list {
            margin-top: 10px;
        }
        
        .email-item {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
        }
        
        .email-item input {
            flex: 1;
        }
        
        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.95) 100%);
            backdrop-filter: blur(10px);
            padding: 15px 20px;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            border: 1px solid rgba(56, 189, 248, 0.3);
            display: none;
            align-items: center;
            gap: 10px;
            z-index: 2000;
            min-width: 300px;
            color: var(--text);
        }
        
        .toast.show {
            display: flex;
            animation: slideIn 0.3s ease;
        }
        
        .toast.success {
            border-left: 4px solid var(--success);
            box-shadow: 0 10px 30px rgba(16, 185, 129, 0.3);
        }
        
        .toast.error {
            border-left: 4px solid var(--danger);
            box-shadow: 0 10px 30px rgba(239, 68, 68, 0.3);
        }
        
        .toast i {
            font-size: 1.2rem;
        }
        
        .toast.success i {
            color: var(--success);
        }
        
        .toast.error i {
            color: var(--danger);
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        /* Scrollbar styling for dark theme */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--dark);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 5px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--primary);
        }
        
        /* Loading animation */
        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.5;
            }
        }
        
        .loading {
            animation: pulse 1.5s ease-in-out infinite;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-network-wired"></i> SNMP Yönetim Paneli</h1>
            <div class="actions">
                <a href="../index.php" class="btn btn-secondary">
                    <i class="fas fa-arrow-left"></i> Ana Sayfa
                </a>
                <button onclick="restartService()" class="btn btn-success">
                    <i class="fas fa-sync-alt"></i> Servisi Yeniden Başlat
                </button>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab-header">
                <button class="tab-button active" data-tab="switches">
                    <i class="fas fa-server"></i> Switch Yönetimi
                </button>
                <button class="tab-button" data-tab="db-switches">
                    <i class="fas fa-database"></i> Veritabanındaki Switchler
                </button>
                <button class="tab-button" data-tab="telegram">
                    <i class="fab fa-telegram"></i> Telegram Ayarları
                </button>
                <button class="tab-button" data-tab="email">
                    <i class="fas fa-envelope"></i> Email Ayarları
                </button>
                <button class="tab-button" data-tab="snmp">
                    <i class="fas fa-key"></i> SNMP Şifreleri
                </button>
                <button class="tab-button" data-tab="alarm-severity">
                    <i class="fas fa-exclamation-triangle"></i> Alarm Seviyeleri
                </button>
            </div>
            
            <!-- Switches Tab -->
            <div class="tab-content active" id="switches">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>SNMP Yapılandırmasındaki Switchler</h2>
                    <div style="display: flex; gap: 10px;">
                        <button onclick="importSnmpToDb()" class="btn btn-success">
                            <i class="fas fa-database"></i> Tümünü DB'ye Aktar
                        </button>
                        <button onclick="openAddSwitchModal()" class="btn btn-primary">
                            <i class="fas fa-plus"></i> Yeni Switch Ekle
                        </button>
                    </div>
                </div>
                
                <div class="switch-list" id="switchList">
                    <!-- Switches will be loaded here -->
                </div>
            </div>
            
            <!-- Database Switches Tab -->
            <div class="tab-content" id="db-switches">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>Veritabanındaki Tüm Switchler</h2>
                    <div style="display: flex; gap: 10px;">
                        <button onclick="loadDbSwitches()" class="btn btn-secondary">
                            <i class="fas fa-sync"></i> Yenile
                        </button>
                        <button onclick="importAllDbSwitches()" class="btn btn-success">
                            <i class="fas fa-file-import"></i> Tümünü SNMP'ye Aktar
                        </button>
                    </div>
                </div>
                
                <div style="background: #e6f7ff; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #1890ff;">
                    <p style="color: #0050b3; margin: 0;">
                        <i class="fas fa-info-circle"></i>
                        <strong>Bilgi:</strong> Burada sistemde kayıtlı tüm switchler gösterilmektedir. Eksik bilgileri tamamlayıp SNMP yapılandırmasına ekleyebilirsiniz.
                    </p>
                </div>
                
                <div class="switch-list" id="dbSwitchList">
                    <p style="text-align: center; color: #718096;">Yükleniyor...</p>
                </div>
            </div>
            
            <!-- Telegram Tab -->
            <div class="tab-content" id="telegram">
                <div class="card">
                    <h3>Telegram Bildirim Ayarları</h3>
                    <form id="telegramForm">
                        <div class="form-group checkbox-group">
                            <input type="checkbox" id="telegram_enabled" name="enabled">
                            <label for="telegram_enabled">Telegram Bildirimleri Aktif</label>
                        </div>
                        
                        <div class="form-group">
                            <label for="bot_token">Bot Token</label>
                            <input type="text" id="bot_token" name="bot_token" placeholder="123456789:ABCdefGHIjklmNOpQRsTUVwxYZ">
                        </div>
                        
                        <div class="form-group">
                            <label for="chat_id">Chat ID</label>
                            <input type="text" id="chat_id" name="chat_id" placeholder="-1001234567890">
                        </div>
                        
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Kaydet
                        </button>
                        
                        <button type="button" onclick="testTelegram()" class="btn btn-success" style="margin-left: 10px;">
                            <i class="fas fa-paper-plane"></i> Test Gönder
                        </button>
                    </form>
                    
                    <div id="telegram-status" style="margin-top: 15px; padding: 10px; border-radius: 5px; display: none;"></div>
                </div>
                
                <div class="card">
                    <h3>Mevcut Yapılandırma</h3>
                    <div id="telegram-current-config" style="background: #f7fafc; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 13px;">
                        <p><strong>Token:</strong> <span id="current-token">Yükleniyor...</span></p>
                        <p><strong>Chat ID:</strong> <span id="current-chat-id">Yükleniyor...</span></p>
                        <p><strong>Durum:</strong> <span id="current-status">Yükleniyor...</span></p>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Telegram Bot Kurulum Kılavuzu</h3>
                    <ol>
                        <li>Telegram'da <strong>@BotFather</strong> hesabını bulun</li>
                        <li><code>/newbot</code> komutunu gönderin</li>
                        <li>Bot için bir isim verin</li>
                        <li>Bot username belirleyin (bot ile bitmeli)</li>
                        <li>Size verilen <strong>token</strong>'ı yukarıdaki alana yapıştırın</li>
                        <li>Botunuzu başlatın ve <strong>@getidsbot</strong> ile chat ID'nizi öğrenin</li>
                    </ol>
                </div>
            </div>
            
            <!-- Email Tab -->
            <div class="tab-content" id="email">
                <div class="card">
                    <h3>Email Bildirim Ayarları</h3>
                    <form id="emailForm">
                        <div class="form-group checkbox-group">
                            <input type="checkbox" id="email_enabled" name="enabled">
                            <label for="email_enabled">Email Bildirimleri Aktif</label>
                        </div>
                        
                        <div class="form-group">
                            <label for="smtp_host">SMTP Sunucu</label>
                            <input type="text" id="smtp_host" name="smtp_host" placeholder="smtp.yandex.com">
                        </div>
                        
                        <div class="form-group">
                            <label for="smtp_port">SMTP Port</label>
                            <input type="number" id="smtp_port" name="smtp_port" placeholder="465">
                        </div>
                        
                        <div class="form-group">
                            <label for="smtp_user">SMTP Kullanıcı (Email)</label>
                            <input type="email" id="smtp_user" name="smtp_user" placeholder="your_email@yandex.com">
                        </div>
                        
                        <div class="form-group">
                            <label for="smtp_password">SMTP Şifre</label>
                            <input type="password" id="smtp_password" name="smtp_password" placeholder="uygulama şifresi" autocomplete="new-password">
                        </div>
                        
                        <div class="form-group">
                            <label for="from_address">Gönderen Email</label>
                            <input type="email" id="from_address" name="from_address" placeholder="noreply@yourcompany.com">
                        </div>
                        
                        <div class="form-group">
                            <label>Alıcı Email Adresleri</label>
                            <div class="email-list" id="emailList">
                                <!-- Email inputs will be added here -->
                            </div>
                            <button type="button" onclick="addEmailInput()" class="btn btn-secondary">
                                <i class="fas fa-plus"></i> Email Ekle
                            </button>
                        </div>
                        
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Kaydet
                        </button>
                    </form>
                </div>
            </div>
            
            <!-- SNMP Tab -->
            <div class="tab-content" id="snmp">
                <div class="card">
                    <h3>SNMP v3 Kimlik Bilgileri</h3>
                    <form id="snmpForm">
                        <div class="form-group">
                            <label for="snmp_version">SNMP Version</label>
                            <select id="snmp_version" name="version">
                                <option value="v3">v3 (Önerilen)</option>
                                <option value="v2c">v2c</option>
                                <option value="v1">v1</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="snmp_username">Kullanıcı Adı</label>
                            <input type="text" id="snmp_username" name="username" autocomplete="username">
                        </div>
                        
                        <div class="form-group">
                            <label for="auth_protocol">Kimlik Doğrulama Protokolü</label>
                            <select id="auth_protocol" name="auth_protocol">
                                <option value="SHA">SHA</option>
                                <option value="MD5">MD5</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="auth_password">Kimlik Doğrulama Şifresi</label>
                            <input type="password" id="auth_password" name="auth_password" autocomplete="new-password">
                        </div>
                        
                        <div class="form-group">
                            <label for="priv_protocol">Şifreleme Protokolü</label>
                            <select id="priv_protocol" name="priv_protocol">
                                <option value="AES">AES</option>
                                <option value="DES">DES</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="priv_password">Şifreleme Şifresi</label>
                            <input type="password" id="priv_password" name="priv_password" autocomplete="new-password">
                        </div>
                        
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Kaydet
                        </button>
                    </form>
                </div>
            </div>
            
            <!-- Alarm Severity Tab -->
            <div class="tab-content" id="alarm-severity">
                <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #ffc107;">
                    <h3 style="color: #856404; margin-bottom: 10px;"><i class="fas fa-info-circle"></i> Alarm Seviye Yönetimi</h3>
                    <p style="color: #856404; margin: 0;">
                        Her alarm tipi için severity seviyesi (CRITICAL/HIGH/MEDIUM/LOW) ve hangi kanallara bildirim gönderileceğini (Telegram/Email) buradan ayarlayabilirsiniz.
                    </p>
                </div>
                
                <div class="card">
                    <h3>Alarm Tipleri ve Seviyeler</h3>
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                            <thead>
                                <tr style="background: #f7fafc; border-bottom: 2px solid #d93025;">
                                    <th style="padding: 12px; text-align: left;">Alarm Tipi</th>
                                    <th style="padding: 12px; text-align: left;">Açıklama</th>
                                    <th style="padding: 12px; text-align: center;">Severity</th>
                                    <th style="padding: 12px; text-align: center;">
                                        <i class="fab fa-telegram" style="color: #0088cc;"></i> Telegram
                                    </th>
                                    <th style="padding: 12px; text-align: center;">
                                        <i class="fas fa-envelope" style="color: #d93025;"></i> Email
                                    </th>
                                    <th style="padding: 12px; text-align: center;">İşlemler</th>
                                </tr>
                            </thead>
                            <tbody id="alarmSeverityTable">
                                <tr>
                                    <td colspan="6" style="text-align: center; padding: 20px; color: #718096;">
                                        <i class="fas fa-spinner fa-spin"></i> Yükleniyor...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Add/Edit Switch Modal -->
    <div class="modal" id="switchModal">
        <div class="modal-content">
            <h2 id="switchModalTitle">Yeni Switch Ekle</h2>
            <form id="switchForm">
                <input type="hidden" id="switch_index" name="index">
                
                <div class="form-group">
                    <label for="switch_name">Switch Adı *</label>
                    <input type="text" id="switch_name" name="name" required>
                </div>
                
                <div class="form-group">
                    <label for="switch_host">IP Adresi *</label>
                    <input type="text" id="switch_host" name="host" required placeholder="192.168.1.1">
                </div>
                
                <div class="form-group">
                    <label for="switch_vendor">Vendor</label>
                    <select id="switch_vendor" name="vendor">
                        <option value="cisco">Cisco</option>
                        <option value="hp">HP</option>
                        <option value="juniper">Juniper</option>
                        <option value="aruba">Aruba</option>
                        <option value="huawei">Huawei</option>
                        <option value="other">Diğer</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="switch_model">Model</label>
                    <input type="text" id="switch_model" name="model" placeholder="örn: CBS350-48FP">
                </div>

                <div class="form-group">
                    <label for="switch_engine_id">Engine ID <small style="color:#94a3b8;">(CBS350 için gereklidir, ör: 0102030405060708)</small></label>
                    <input type="text" id="switch_engine_id" name="engine_id" placeholder="0102030405060708">
                </div>
                
                <div class="form-group">
                    <label for="switch_description">Açıklama</label>
                    <textarea id="switch_description" name="description" rows="3"></textarea>
                </div>
                
                <div class="form-group checkbox-group">
                    <input type="checkbox" id="switch_enabled" name="enabled" checked>
                    <label for="switch_enabled">Aktif</label>
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 20px;">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Kaydet
                    </button>
                    <button type="button" onclick="closeModal()" class="btn btn-secondary">
                        <i class="fas fa-times"></i> İptal
                    </button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Toast Notification -->
    <div class="toast" id="toast">
        <i class="fas fa-check-circle"></i>
        <span id="toastMessage"></span>
    </div>
    
    <script>
        let currentConfig = <?php echo json_encode($config); ?>;
        
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                button.classList.add('active');
                document.getElementById(button.dataset.tab).classList.add('active');
            });
        });
        
        // Load switches
        function loadSwitches() {
            const container = document.getElementById('switchList');
            container.innerHTML = '';
            
            if (!currentConfig.switches || currentConfig.switches.length === 0) {
                container.innerHTML = '<p style="text-align: center; color: #718096;">Henüz switch eklenmemiş</p>';
                return;
            }
            
            currentConfig.switches.forEach((sw, index) => {
                const card = document.createElement('div');
                card.className = 'switch-card';
                card.innerHTML = `
                    <h4>
                        <i class="fas fa-server"></i>
                        ${sw.name}
                        <span class="status-badge ${sw.enabled ? 'enabled' : 'disabled'}">
                            ${sw.enabled ? 'Aktif' : 'Pasif'}
                        </span>
                    </h4>
                    <p><strong>IP:</strong> ${sw.host}</p>
                    <p><strong>Vendor:</strong> ${sw.vendor}</p>
                    ${sw.model ? `<p><strong>Model:</strong> ${sw.model}</p>` : ''}
                    ${sw.description ? `<p><strong>Açıklama:</strong> ${sw.description}</p>` : ''}
                    <div class="actions">
                        <button onclick="editSwitch(${index})" class="btn btn-primary">
                            <i class="fas fa-edit"></i> Düzenle
                        </button>
                        <button onclick="deleteSwitch(${index})" class="btn btn-danger">
                            <i class="fas fa-trash"></i> Sil
                        </button>
                    </div>
                `;
                container.appendChild(card);
            });
        }
        
        // Load Telegram config
        function loadTelegramConfig() {
            if (currentConfig.telegram) {
                document.getElementById('telegram_enabled').checked = currentConfig.telegram.enabled;
                document.getElementById('bot_token').value = currentConfig.telegram.bot_token;
                document.getElementById('chat_id').value = currentConfig.telegram.chat_id;
                
                // Update current config display
                document.getElementById('current-token').textContent = currentConfig.telegram.bot_token || 'Yapılandırılmamış';
                document.getElementById('current-chat-id').textContent = currentConfig.telegram.chat_id || 'Yapılandırılmamış';
                document.getElementById('current-status').innerHTML = currentConfig.telegram.enabled ? 
                    '<span style="color: #48bb78;">✅ Aktif</span>' : 
                    '<span style="color: #f56565;">❌ Pasif</span>';
            }
        }
        
        // Test Telegram notification
        function testTelegram() {
            const token = document.getElementById('bot_token').value;
            const chatId = document.getElementById('chat_id').value;
            
            if (!token || !chatId) {
                showToast('Lütfen Bot Token ve Chat ID değerlerini girin', 'error');
                return;
            }
            
            const statusDiv = document.getElementById('telegram-status');
            statusDiv.style.display = 'block';
            statusDiv.style.background = '#edf2f7';
            statusDiv.style.color = '#2d3748';
            statusDiv.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Test mesajı gönderiliyor...';
            
            // Use server-side endpoint to avoid CORS issues
            fetch('snmp_admin.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    action: 'test_telegram',
                    bot_token: token,
                    chat_id: chatId
                })
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    statusDiv.style.background = '#c6f6d5';
                    statusDiv.style.color = '#22543d';
                    statusDiv.innerHTML = '<i class="fas fa-check-circle"></i> ✅ ' + result.message;
                    showToast('Test mesajı gönderildi!', 'success');
                } else {
                    statusDiv.style.background = '#fed7d7';
                    statusDiv.style.color = '#742a2a';
                    statusDiv.innerHTML = `<i class="fas fa-exclamation-circle"></i> ❌ ${result.error}`;
                    showToast('Test başarısız: ' + result.error, 'error');
                }
            })
            .catch(error => {
                statusDiv.style.background = '#fed7d7';
                statusDiv.style.color = '#742a2a';
                statusDiv.innerHTML = `<i class="fas fa-exclamation-circle"></i> ❌ Bağlantı hatası: ${error.message}`;
                showToast('Test başarısız: ' + error.message, 'error');
            });
        }
        
        // Load Email config
        function loadEmailConfig() {
            if (currentConfig.email) {
                document.getElementById('email_enabled').checked = currentConfig.email.enabled;
                document.getElementById('smtp_host').value = currentConfig.email.smtp_host;
                document.getElementById('smtp_port').value = currentConfig.email.smtp_port;
                document.getElementById('smtp_user').value = currentConfig.email.smtp_user;
                document.getElementById('smtp_password').value = currentConfig.email.smtp_password;
                document.getElementById('from_address').value = currentConfig.email.from_address;
                
                // Load email addresses
                const emailList = document.getElementById('emailList');
                emailList.innerHTML = '';
                if (currentConfig.email.to_addresses) {
                    currentConfig.email.to_addresses.forEach(email => {
                        addEmailInput(email);
                    });
                }
                if (emailList.children.length === 0) {
                    addEmailInput();
                }
            }
        }
        
        // Load SNMP config
        function loadSNMPConfig() {
            if (currentConfig.snmp) {
                document.getElementById('snmp_version').value = currentConfig.snmp.version;
                document.getElementById('snmp_username').value = currentConfig.snmp.username;
                document.getElementById('auth_protocol').value = currentConfig.snmp.auth_protocol;
                document.getElementById('auth_password').value = currentConfig.snmp.auth_password;
                document.getElementById('priv_protocol').value = currentConfig.snmp.priv_protocol;
                document.getElementById('priv_password').value = currentConfig.snmp.priv_password;
            }
        }
        
        // Add email input
        function addEmailInput(value = '') {
            const emailList = document.getElementById('emailList');
            const div = document.createElement('div');
            div.className = 'email-item';
            div.innerHTML = `
                <input type="email" name="to_addresses[]" value="${value}" placeholder="email@example.com">
                <button type="button" onclick="this.parentElement.remove()" class="btn btn-danger">
                    <i class="fas fa-trash"></i>
                </button>
            `;
            emailList.appendChild(div);
        }
        
        // Open add switch modal
        function openAddSwitchModal() {
            document.getElementById('switchModalTitle').textContent = 'Yeni Switch Ekle';
            document.getElementById('switchForm').reset();
            document.getElementById('switch_index').value = '';
            document.getElementById('switch_enabled').checked = true;
            document.getElementById('switchModal').classList.add('active');
        }
        
        // Edit switch
        function editSwitch(index) {
            const sw = currentConfig.switches[index];
            document.getElementById('switchModalTitle').textContent = 'Switch Düzenle';
            document.getElementById('switch_index').value = index;
            document.getElementById('switch_name').value = sw.name;
            document.getElementById('switch_host').value = sw.host;
            document.getElementById('switch_vendor').value = sw.vendor;
            document.getElementById('switch_model').value = sw.model;
            document.getElementById('switch_description').value = sw.description;
            document.getElementById('switch_enabled').checked = sw.enabled;
            // Populate engine_id if present in per-switch snmp_v3 config
            const engineId = (sw.snmp_v3 && sw.snmp_v3.engine_id) ? sw.snmp_v3.engine_id : '';
            document.getElementById('switch_engine_id').value = engineId;
            document.getElementById('switchModal').classList.add('active');
        }
        
        // Delete switch
        function deleteSwitch(index) {
            if (!confirm('Bu switch\'i silmek istediğinizden emin misiniz?')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'delete_switch');
            formData.append('index', index);
            
            fetch('snmp_admin.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    reloadConfig();
                } else {
                    showToast(data.error, 'error');
                }
            });
        }
        
        // Close modal
        function closeModal() {
            document.getElementById('switchModal').classList.remove('active');
        }
        
        // Show toast
        function showToast(message, type = 'success') {
            const toast = document.getElementById('toast');
            const toastMessage = document.getElementById('toastMessage');
            
            toastMessage.textContent = message;
            toast.className = `toast show ${type}`;
            
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }
        
        // Reload config
        function reloadConfig() {
            fetch('snmp_admin.php?action=get_config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=get_config'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentConfig = data.config;
                    loadSwitches();
                    loadTelegramConfig();
                    loadEmailConfig();
                    loadSNMPConfig();
                }
            });
        }
        
        // Restart service
        function restartService() {
            if (confirm('SNMP servisini yeniden başlatmak istediğinizden emin misiniz?')) {
                showToast('Servis yeniden başlatılıyor... (Windows servisi için manuel başlatma gerekebilir)', 'success');
            }
        }
        
        // Form submissions
        document.getElementById('switchForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const index = formData.get('index');
            formData.set('action', index !== '' ? 'update_switch' : 'add_switch');
            formData.set('enabled', document.getElementById('switch_enabled').checked ? 'true' : 'false');
            
            fetch('snmp_admin.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    closeModal();
                    reloadConfig();
                } else {
                    showToast(data.error, 'error');
                }
            });
        });
        
        document.getElementById('telegramForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.set('action', 'update_telegram');
            formData.set('enabled', document.getElementById('telegram_enabled').checked ? 'true' : 'false');
            
            fetch('snmp_admin.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    reloadConfig();
                } else {
                    showToast(data.error, 'error');
                }
            });
        });
        
        document.getElementById('emailForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.set('action', 'update_email');
            formData.set('enabled', document.getElementById('email_enabled').checked ? 'true' : 'false');
            
            // Collect email addresses
            const emails = Array.from(document.querySelectorAll('input[name="to_addresses[]"]'))
                .map(input => input.value)
                .filter(email => email.trim() !== '');
            
            formData.delete('to_addresses[]');
            emails.forEach((email, index) => {
                formData.append('to_addresses[]', email);
            });
            
            fetch('snmp_admin.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    reloadConfig();
                } else {
                    showToast(data.error, 'error');
                }
            });
        });
        
        document.getElementById('snmpForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.set('action', 'update_snmp');
            
            fetch('snmp_admin.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    reloadConfig();
                } else {
                    showToast(data.error, 'error');
                }
            });
        });
        
        // Load database switches
        function loadDbSwitches() {
            const container = document.getElementById('dbSwitchList');
            container.innerHTML = '<p style="text-align: center; color: #718096;">Yükleniyor...</p>';
            
            const formData = new FormData();
            formData.append('action', 'get_db_switches');
            
            fetch('snmp_admin.php', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                console.log('Response status:', response.status);
                console.log('Response ok:', response.ok);
                return response.text();
            })
            .then(text => {
                console.log('Response text:', text);
                try {
                    const data = JSON.parse(text);
                    if (data.success) {
                        displayDbSwitches(data.switches);
                    } else {
                        container.innerHTML = `<p style="text-align: center; color: #f56565;">${data.error}</p>`;
                    }
                } catch (e) {
                    console.error('JSON parse error:', e);
                    container.innerHTML = `<p style="text-align: center; color: #f56565;">JSON hatası: ${e.message}<br><br>Response: ${text.substring(0, 200)}</p>`;
                }
            })
            .catch(error => {
                console.error('Fetch error:', error);
                container.innerHTML = `<p style="text-align: center; color: #f56565;">Veri yüklenirken hata oluştu: ${error.message}</p>`;
            });
        }
        
        // Display database switches
        function displayDbSwitches(switches) {
            const container = document.getElementById('dbSwitchList');
            container.innerHTML = '';
            
            if (!switches || switches.length === 0) {
                container.innerHTML = '<p style="text-align: center; color: #718096;">Veritabanında switch bulunamadı</p>';
                return;
            }
            
            switches.forEach(sw => {
                const card = document.createElement('div');
                card.className = 'switch-card';
                
                const isInConfig = sw.in_snmp_config;
                const statusBadge = isInConfig 
                    ? '<span class="status-badge enabled">SNMP\'de Var</span>'
                    : '<span class="status-badge disabled">SNMP\'de Yok</span>';
                
                const importButton = !isInConfig
                    ? `<button onclick="importDbSwitch(${sw.id})" class="btn btn-success">
                            <i class="fas fa-file-import"></i> SNMP'ye Ekle
                       </button>`
                    : '<button class="btn btn-secondary" disabled>Zaten Eklendi</button>';
                
                card.innerHTML = `
                    <h4>
                        <i class="fas fa-server"></i>
                        ${sw.name}
                        ${statusBadge}
                    </h4>
                    <p><strong>IP:</strong> ${sw.ip || '<span style="color: #f56565;">Eksik</span>'}</p>
                    <p><strong>Vendor:</strong> ${sw.vendor || '<span style="color: #cbd5e0;">Belirtilmemiş</span>'}</p>
                    ${sw.model ? `<p><strong>Model:</strong> ${sw.model}</p>` : ''}
                    ${sw.description ? `<p><strong>Açıklama:</strong> ${sw.description}</p>` : ''}
                    <p><strong>Port Sayısı:</strong> ${sw.ports || 'Belirtilmemiş'}</p>
                    ${!sw.ip ? '<p style="color: #f56565; font-size: 12px;"><i class="fas fa-exclamation-triangle"></i> IP adresi eksik! SNMP\'ye eklenemez.</p>' : ''}
                    <div class="actions">
                        ${sw.ip ? importButton : '<button class="btn btn-secondary" disabled>IP Eksik</button>'}
                        <a href="../index.php?switch_id=${sw.id}" class="btn btn-primary" target="_blank">
                            <i class="fas fa-edit"></i> Düzenle
                        </a>
                    </div>
                `;
                container.appendChild(card);
            });
        }
        
        // Import single switch from database
        function importDbSwitch(switchId) {
            if (!confirm('Bu switch\'i SNMP yapılandırmasına eklemek istiyor musunuz?')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'import_from_db');
            formData.append('switch_id', switchId);
            
            fetch('snmp_admin.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    loadDbSwitches(); // Reload DB switches list
                    reloadConfig(); // Reload SNMP config
                } else {
                    showToast(data.error, 'error');
                }
            });
        }
        
        // Import all switches from database
        function importAllDbSwitches() {
            if (!confirm('Veritabanındaki TÜM switchleri SNMP yapılandırmasına eklemek istiyor musunuz? (Sadece SNMP\'de olmayan ve IP adresi olan switchler eklenecek)')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'import_all_from_db');
            
            fetch('snmp_admin.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    loadDbSwitches(); // Reload DB switches list
                    reloadConfig(); // Reload SNMP config
                } else {
                    showToast(data.error, 'error');
                }
            });
        }

        // Import all SNMP config switches into the database (reverse of importAllDbSwitches)
        function importSnmpToDb() {
            if (!confirm('SNMP yapılandırmasındaki TÜM switchleri veritabanına eklemek istiyor musunuz? (Zaten mevcut olanlar atlanır)')) {
                return;
            }

            const formData = new FormData();
            formData.append('action', 'import_snmp_to_db');

            fetch('snmp_admin.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    loadDbSwitches(); // Refresh DB list so new entries appear
                } else {
                    showToast(data.error, 'error');
                }
            })
            .catch(err => showToast('Hata: ' + err.message, 'error'));
        }
        
        // Initialize
        loadSwitches();
        loadTelegramConfig();
        loadEmailConfig();
        loadSNMPConfig();
        loadDbSwitches(); // Load database switches on start
        loadAlarmSeverities(); // Load alarm severities
        
        // Load alarm severity configuration
        function loadAlarmSeverities() {
            fetch('snmp_admin.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    action: 'get_alarm_severities'
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayAlarmSeverities(data.severities);
                } else {
                    document.getElementById('alarmSeverityTable').innerHTML = `
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 20px; color: #e53e3e;">
                                <i class="fas fa-exclamation-triangle"></i> ${data.error}
                            </td>
                        </tr>
                    `;
                }
            })
            .catch(error => {
                document.getElementById('alarmSeverityTable').innerHTML = `
                    <tr>
                        <td colspan="6" style="text-align: center; padding: 20px; color: #e53e3e;">
                            <i class="fas fa-exclamation-triangle"></i> Yükleme hatası: ${error.message}
                        </td>
                    </tr>
                `;
            });
        }
        
        // Display alarm severities in table
        function displayAlarmSeverities(severities) {
            const table = document.getElementById('alarmSeverityTable');
            
            if (!severities || severities.length === 0) {
                table.innerHTML = `
                    <tr>
                        <td colspan="6" style="text-align: center; padding: 20px; color: #718096;">
                            Henüz alarm seviyesi tanımlanmamış
                        </td>
                    </tr>
                `;
                return;
            }
            
            const severityColors = {
                'CRITICAL': '#e53e3e',
                'HIGH': '#ed8936',
                'MEDIUM': '#ecc94b',
                'LOW': '#48bb78'
            };
            
            table.innerHTML = severities.map(item => `
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 12px; font-weight: 500; color: #2d3748;">
                        ${item.alarm_type}
                    </td>
                    <td style="padding: 12px; color: #718096; font-size: 13px;">
                        ${item.description || '-'}
                    </td>
                    <td style="padding: 12px; text-align: center;">
                        <select id="severity_${item.alarm_type}" class="severity-select" 
                                style="padding: 6px 12px; border: 2px solid ${severityColors[item.severity]}; 
                                       border-radius: 5px; background: ${severityColors[item.severity]}20; 
                                       color: ${severityColors[item.severity]}; font-weight: bold; cursor: pointer;">
                            <option value="CRITICAL" ${item.severity === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
                            <option value="HIGH" ${item.severity === 'HIGH' ? 'selected' : ''}>HIGH</option>
                            <option value="MEDIUM" ${item.severity === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
                            <option value="LOW" ${item.severity === 'LOW' ? 'selected' : ''}>LOW</option>
                        </select>
                    </td>
                    <td style="padding: 12px; text-align: center;">
                        <label class="checkbox-switch">
                            <input type="checkbox" id="telegram_${item.alarm_type}" 
                                   ${item.telegram_enabled ? 'checked' : ''}>
                            <span class="slider"></span>
                        </label>
                    </td>
                    <td style="padding: 12px; text-align: center;">
                        <label class="checkbox-switch">
                            <input type="checkbox" id="email_${item.alarm_type}" 
                                   ${item.email_enabled ? 'checked' : ''}>
                            <span class="slider"></span>
                        </label>
                    </td>
                    <td style="padding: 12px; text-align: center;">
                        <button onclick="updateAlarmSeverity('${item.alarm_type}')" 
                                class="btn btn-primary" style="padding: 6px 12px; font-size: 12px;">
                            <i class="fas fa-save"></i> Kaydet
                        </button>
                    </td>
                </tr>
            `).join('');
        }
        
        // Update alarm severity
        function updateAlarmSeverity(alarmType) {
            const severity = document.getElementById(`severity_${alarmType}`).value;
            const telegramEnabled = document.getElementById(`telegram_${alarmType}`).checked;
            const emailEnabled = document.getElementById(`email_${alarmType}`).checked;
            
            fetch('snmp_admin.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    action: 'update_alarm_severity',
                    alarm_type: alarmType,
                    severity: severity,
                    telegram_enabled: telegramEnabled,
                    email_enabled: emailEnabled
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    loadAlarmSeverities(); // Reload to show updated colors
                } else {
                    showToast(data.error, 'error');
                }
            })
            .catch(error => {
                showToast('Güncelleme hatası: ' + error.message, 'error');
            });
        }
    </script>
    
    <style>
        /* Checkbox switch for alarm severities */
        .checkbox-switch {
            position: relative;
            display: inline-block;
            width: 50px;
            height: 24px;
        }
        
        .checkbox-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .checkbox-switch .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 24px;
        }
        
        .checkbox-switch .slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        
        .checkbox-switch input:checked + .slider {
            background-color: #48bb78;
        }
        
        .checkbox-switch input:checked + .slider:before {
            transform: translateX(26px);
        }
        
        .severity-select {
            transition: all 0.3s;
        }
        
        .severity-select:hover {
            opacity: 0.8;
        }
    </style>
</body>
</html>
