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
// Release the PHP session lock immediately so that concurrent requests from
// admin.php (service-status poll, panel CSV export, etc.) are not blocked.
session_write_close();

// Path to the active SNMP worker configuration file.
// Must be defined before any call to parseYamlConfig / saveYamlConfig.
$configPath = __DIR__ . '/../snmp_worker/config/config.yml';

// YAML parser for PHP
function parseYamlConfig($filename) {
    // Auto-create config.yml from the example file when it doesn't exist yet
    // (fresh install / first run).  This prevents "Config dosyası okunamadı"
    // errors the very first time an admin visits the page.
    if (!file_exists($filename)) {
        $exampleFile = dirname($filename) . '/config.example.yml';
        if (file_exists($exampleFile)) {
            @copy($exampleFile, $filename);
        }
    }
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
        $config['switches'][] = [
            'name' => $match[1],
            'host' => $match[2],
            'vendor' => $match[3],
            'model' => $match[4],
            'enabled' => $match[5] === 'true',
            'description' => $match[6]
        ];
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
    }
    
    // Parse Telegram (allow empty bot_token / chat_id)
    if (preg_match('/telegram:\s+enabled: (true|false)\s+bot_token: "([^"]*)"\s+chat_id: "([^"]*)"/s', $content, $match)) {
        $config['telegram'] = [
            'enabled' => $match[1] === 'true',
            'bot_token' => $match[2],
            'chat_id' => $match[3]
        ];
    } else {
        $config['telegram'] = ['enabled' => false, 'bot_token' => '', 'chat_id' => ''];
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
        // Parse to_addresses — extract only items inside the to_addresses block.
        // The outer regex's \s* consumes the newline+spaces before the first list
        // item, so $taBlock[1] may start with "- ..." (no leading spaces).
        // Using \s* (not \s+) in the inner pattern handles both the first item
        // (no leading indent) and subsequent items (with leading indent).
        $toAddresses = [];
        if (preg_match('/to_addresses:\s*(.*?)(?=\n\s*[a-z_]+:|\Z)/s', $content, $taBlock)) {
            preg_match_all('/^\s*- "([^"]+)"/m', $taBlock[1], $taMatches);
            $toAddresses = $taMatches[1] ?? [];
        }
        $config['email']['to_addresses'] = $toAddresses;
    }
    
    // Parse alarms block (lines indented under 'alarms:')
    $alarmConfig = [
        'enabled' => true,
        'debounce_time' => 60,
        'unreachable_threshold' => 3,
        'trigger_on' => ['port_down', 'device_unreachable', 'snmp_error'],
        'vlan_exclude' => []
    ];
    if (preg_match('/^alarms:\s*\n((?:[ \t][^\n]*\n?|[ \t]*\n)*)/m', $content, $alarmsMatch)) {
        $ab = $alarmsMatch[1];
        if (preg_match('/^\s+unreachable_threshold:\s*(\d+)/m', $ab, $m))
            $alarmConfig['unreachable_threshold'] = (int)$m[1];
        // trigger_on list
        if (preg_match('/^\s+trigger_on:\s*\n((?:\s+- [^\n]+\n?)*)/m', $ab, $m)) {
            preg_match_all('/^\s+- (.+)$/m', $m[1], $items);
            if (!empty($items[1])) $alarmConfig['trigger_on'] = array_map('trim', $items[1]);
        }
        // vlan_exclude list
        if (preg_match('/^\s+vlan_exclude:\s*\n((?:\s+- \d+\n?)*)/m', $ab, $m)) {
            preg_match_all('/^\s+- (\d+)$/m', $m[1], $items);
            if (!empty($items[1])) $alarmConfig['vlan_exclude'] = array_map('intval', $items[1]);
        }
        // severity_routing: preserve raw YAML for round-trip.
        // NOTE: _severity_routing_raw is only ever populated from the file
        // by this parser — it is never written by user input — so it is safe
        // to embed verbatim into the saved YAML output.
        $srPos = strpos($ab, '  severity_routing:');
        if ($srPos !== false)
            $alarmConfig['_severity_routing_raw'] = rtrim(substr($ab, $srPos));
    }
    $config['alarms'] = $alarmConfig;
    
    // Parse per-switch engine_id / snmp_port / trap_port / snmp_v3 credentials
    foreach ($config['switches'] as &$sw) {
        $escapedName = preg_quote($sw['name'], '/');
        if (preg_match('/- name: "' . $escapedName . '"(.*?)(?=\n  - name:|\Z)/s', $content, $swBlock)) {
            $sb = $swBlock[1];
            if (preg_match('/engine_id:\s*"([^"]+)"/', $sb, $m))  $sw['engine_id']  = $m[1];
            if (preg_match('/snmp_port:\s*(\d+)/',     $sb, $m))  $sw['snmp_port']  = (int)$m[1];
            if (preg_match('/trap_port:\s*(\d+)/',     $sb, $m))  $sw['trap_port']  = (int)$m[1];
            // Parse per-switch snmp_v3 credentials so they survive round-trips through the UI
            // without being replaced by the global snmp: credentials.
            $v3creds = [];
            if (preg_match('/auth_password:\s*"([^"]*)"/',  $sb, $m2)) $v3creds['auth_password']  = $m2[1];
            if (preg_match('/auth_protocol:\s*"([^"]*)"/',  $sb, $m2)) $v3creds['auth_protocol']  = $m2[1];
            if (preg_match('/priv_password:\s*"([^"]*)"/',  $sb, $m2)) $v3creds['priv_password']  = $m2[1];
            if (preg_match('/priv_protocol:\s*"([^"]*)"/',  $sb, $m2)) $v3creds['priv_protocol']  = $m2[1];
            if (preg_match('/\busername:\s*"([^"]*)"/',     $sb, $m2)) $v3creds['username']       = $m2[1];
            if (!empty($v3creds)) $sw['snmp_v3'] = $v3creds;
        }
    }
    unset($sw);
    
    // Store raw file content so saveYamlConfig can preserve unmanaged sections
    $config['_raw'] = $content;
    // Store raw polling block so saveYamlConfig can round-trip all tuned parameters
    // (snmp_stagger_ms, db_max_workers, polling_data_interval, mac_poll_interval, etc.)
    if (preg_match('/^(# Polling[^\n]*\n)?polling:\s*\n((?:[ \t][^\n]*\n?|[ \t]*\n)*)/m', $content, $pm)) {
        $config['_polling_raw'] = rtrim($pm[0]);
    }
    // Parse individual polling values for UI display and update actions.
    $config['polling'] = [
        'interval'                => 60,
        'mac_poll_interval'       => 60,
        'port_poll_interval'      => 60,
        'device_info_poll_interval' => 120,
        'snmp_stagger_ms'         => 300,
        'db_max_workers'          => 2,
        'max_workers'             => 10,
    ];
    if (!empty($config['_polling_raw'])) {
        $pb = $config['_polling_raw'];
        if (preg_match('/interval:\s*(\d+)/m',                  $pb, $m)) $config['polling']['interval']                 = (int)$m[1];
        if (preg_match('/mac_poll_interval:\s*(\d+)/m',         $pb, $m)) $config['polling']['mac_poll_interval']        = (int)$m[1];
        if (preg_match('/port_poll_interval:\s*(\d+)/m',        $pb, $m)) $config['polling']['port_poll_interval']       = (int)$m[1];
        if (preg_match('/device_info_poll_interval:\s*(\d+)/m', $pb, $m)) $config['polling']['device_info_poll_interval']= (int)$m[1];
        if (preg_match('/snmp_stagger_ms:\s*(\d+)/m',           $pb, $m)) $config['polling']['snmp_stagger_ms']         = (int)$m[1];
        if (preg_match('/db_max_workers:\s*(\d+)/m',            $pb, $m)) $config['polling']['db_max_workers']          = (int)$m[1];
        if (preg_match('/max_workers:\s*(\d+)/m',               $pb, $m)) $config['polling']['max_workers']             = (int)$m[1];
    }
    
    return $config;
}

function saveYamlConfig($filename, $config) {
    // Sanitize a string value for YAML double-quoted strings.
    // The PHP regex-based parser uses [^"]* (no unescaping), so we must not
    // produce \" inside captured strings — instead, strip chars that would
    // break parsing.  Real SMTP/SNMP passwords and tokens never contain these.
    // Backslash is also stripped: pyyaml 6.0+ raises ScannerError for unknown
    // escape sequences like \s in double-quoted YAML strings.
    $yamlStr = function($v) {
        $v = (string)($v ?? '');
        $v = str_replace(['"', '\\', "\r\n", "\r", "\n", "\t", "\0"], ['', '', ' ', '', ' ', ' ', ''], $v);
        return $v;
    };

    $yaml = "# SNMP Worker Configuration\n";
    $yaml .= "# Active configuration file for SNMP monitoring\n\n";
    
    // Database
    $yaml .= "# Database Configuration (PostgreSQL/MySQL)\n";
    $yaml .= "database:\n";
    $yaml .= "  host: " . ($config['database']['host'] ?? '127.0.0.1') . "\n";
    $yaml .= "  port: " . ($config['database']['port'] ?? 3306) . "\n";
    $yaml .= "  name: " . ($config['database']['name'] ?? 'switchdb') . "\n";
    $yaml .= "  user: " . ($config['database']['user'] ?? 'root') . "\n";
    $yaml .= "  password: \"" . $yamlStr($config['database']['password'] ?? '') . "\"\n";
    $yaml .= "  pool_size: 10\n";
    $yaml .= "  max_overflow: 20\n\n";
    
    // SNMP
    $yaml .= "# Global SNMP Configuration\n";
    $yaml .= "snmp:\n";
    $yaml .= "  version: \"" . $yamlStr($config['snmp']['version'] ?? '3') . "\"\n";
    $yaml .= "  username: \"" . $yamlStr($config['snmp']['username'] ?? 'snmpuser') . "\"\n";
    $yaml .= "  auth_protocol: \"" . $yamlStr($config['snmp']['auth_protocol'] ?? 'SHA') . "\"\n";
    $yaml .= "  auth_password: \"" . $yamlStr($config['snmp']['auth_password'] ?? '') . "\"\n";
    $yaml .= "  priv_protocol: \"" . $yamlStr($config['snmp']['priv_protocol'] ?? 'AES') . "\"\n";
    $yaml .= "  priv_password: \"" . $yamlStr($config['snmp']['priv_password'] ?? '') . "\"\n";
    $yaml .= "  timeout: 2\n";
    $yaml .= "  retries: 1\n";
    $yaml .= "  max_bulk_size: 100\n\n";
    
    // Polling — emit the raw block preserved from the original file so that all
    // tuned parameters (snmp_stagger_ms, db_max_workers, polling_data_interval,
    // mac_poll_interval, device_info_poll_interval, port_poll_interval, …) are
    // kept intact when the admin saves only email/SNMP/telegram settings.
    // If $config['polling'] contains updated values (from update_polling action),
    // patch the corresponding lines in the raw block before emitting it.
    if (!empty($config['_polling_raw'])) {
        $rawPolling = $config['_polling_raw'];
        if (!empty($config['polling'])) {
            $patchMap = [
                'interval'                 => 'interval',
                'mac_poll_interval'        => 'mac_poll_interval',
                'port_poll_interval'       => 'port_poll_interval',
                'device_info_poll_interval'=> 'device_info_poll_interval',
                'snmp_stagger_ms'          => 'snmp_stagger_ms',
                'db_max_workers'           => 'db_max_workers',
                'max_workers'              => 'max_workers',
            ];
            foreach ($patchMap as $key => $yamlKey) {
                if (isset($config['polling'][$key]) && $config['polling'][$key] !== null) {
                    $val = (int)$config['polling'][$key];
                    $rawPolling = preg_replace(
                        '/^(\s+' . preg_quote($yamlKey, '/') . ':\s*)\d+/m',
                        '${1}' . $val,
                        $rawPolling
                    );
                }
            }
        }
        $yaml .= $rawPolling . "\n\n";
    } else {
        $yaml .= "# Polling Configuration\n";
        $yaml .= "polling:\n";
        $yaml .= "  interval: " . (int)($config['polling']['interval'] ?? 60) . "\n";
        $yaml .= "  parallel_devices: 15\n";
        $yaml .= "  max_workers: " . (int)($config['polling']['max_workers'] ?? 10) . "\n\n";
    }
    
    // Switches — always include snmp_version + snmp_v3 block so worker gets correct credentials
    $snmp = $config['snmp'] ?? [];
    $yaml .= "# Switches Configuration\n";
    $yaml .= "switches:\n";
    foreach ($config['switches'] as $switch) {
        $yaml .= "  - name: \"" . $switch['name'] . "\"\n";
        $yaml .= "    host: \"" . $switch['host'] . "\"\n";
        $yaml .= "    vendor: \"" . $switch['vendor'] . "\"\n";
        $yaml .= "    model: \"" . $switch['model'] . "\"\n";
        $yaml .= "    enabled: " . ($switch['enabled'] ? 'true' : 'false') . "\n";
        $yaml .= "    description: \"" . $switch['description'] . "\"\n";
        $yaml .= "    snmp_version: \"3\"\n";
        if (!empty($switch['snmp_port']))
            $yaml .= "    snmp_port: " . (int)$switch['snmp_port'] . "\n";
        if (!empty($switch['trap_port']))
            $yaml .= "    trap_port: " . (int)$switch['trap_port'] . "\n";
        $yaml .= "    snmp_v3:\n";
        // Use per-switch snmp_v3 credentials when they exist (preserves switches that have
        // different passwords from the global snmp: block, e.g. SW23-BALO / SW24-BALO).
        // Fall back to the global snmp: credentials only when the switch has none of its own.
        $swSnmp = !empty($switch['snmp_v3']) ? $switch['snmp_v3'] : $snmp;
        $yaml .= "      username: \"" . $yamlStr($swSnmp['username'] ?? $snmp['username'] ?? 'snmpuser') . "\"\n";
        $yaml .= "      auth_protocol: \"" . $yamlStr($swSnmp['auth_protocol'] ?? $snmp['auth_protocol'] ?? 'SHA') . "\"\n";
        $yaml .= "      auth_password: \"" . $yamlStr($swSnmp['auth_password'] ?? $snmp['auth_password'] ?? '') . "\"\n";
        $yaml .= "      priv_protocol: \"" . $yamlStr($swSnmp['priv_protocol'] ?? $snmp['priv_protocol'] ?? 'AES') . "\"\n";
        $yaml .= "      priv_password: \"" . $yamlStr($swSnmp['priv_password'] ?? $snmp['priv_password'] ?? '') . "\"\n";
        if (!empty($switch['engine_id']))
            $yaml .= "      engine_id: \"" . $switch['engine_id'] . "\"\n";
        $yaml .= "\n";
    }
    
    // Alarms — write full config so no settings are lost on each admin save
    $alarms = $config['alarms'] ?? [];
    $yaml .= "# Alarm Configuration\n";
    $yaml .= "alarms:\n";
    $yaml .= "  enabled: " . (($alarms['enabled'] ?? true) ? 'true' : 'false') . "\n";
    $yaml .= "  debounce_time: " . (int)($alarms['debounce_time'] ?? 60) . "\n";
    $yaml .= "  unreachable_threshold: " . (int)($alarms['unreachable_threshold'] ?? 3) . "\n";
    $yaml .= "  trigger_on:\n";
    $triggerOn = $alarms['trigger_on'] ?? ['port_down', 'device_unreachable', 'snmp_error'];
    foreach ($triggerOn as $t) {
        $yaml .= "    - " . trim($t) . "\n";
    }
    $vlanExclude = $alarms['vlan_exclude'] ?? [];
    if (!empty($vlanExclude)) {
        $yaml .= "  vlan_exclude:\n";
        foreach ($vlanExclude as $vlan) {
            $yaml .= "    - " . (int)$vlan . "\n";
        }
    }
    if (!empty($alarms['_severity_routing_raw'])) {
        $yaml .= $alarms['_severity_routing_raw'] . "\n";
    }
    $yaml .= "\n";
    
    // Telegram
    $yaml .= "# Telegram Notifications\n";
    $yaml .= "telegram:\n";
    $yaml .= "  enabled: " . ($config['telegram']['enabled'] ? 'true' : 'false') . "\n";
    $yaml .= "  bot_token: \"" . $yamlStr($config['telegram']['bot_token'] ?? '') . "\"\n";
    $yaml .= "  chat_id: \"" . $yamlStr($config['telegram']['chat_id'] ?? '') . "\"\n";
    $yaml .= "  notify_on:\n";
    $yaml .= "    - port_down\n";
    $yaml .= "    - port_up\n";
    $yaml .= "    - device_unreachable\n\n";
    
    // Email
    $yaml .= "# Email Notifications\n";
    $yaml .= "email:\n";
    $yaml .= "  enabled: " . ($config['email']['enabled'] ? 'true' : 'false') . "\n";
    $yaml .= "  smtp_host: \"" . $yamlStr($config['email']['smtp_host'] ?? '') . "\"\n";
    $yaml .= "  smtp_port: " . (int)($config['email']['smtp_port'] ?? 465) . "\n";
    $yaml .= "  smtp_user: \"" . $yamlStr($config['email']['smtp_user'] ?? '') . "\"\n";
    $yaml .= "  smtp_password: \"" . $yamlStr($config['email']['smtp_password'] ?? '') . "\"\n";
    $yaml .= "  from_address: \"" . $yamlStr($config['email']['from_address'] ?? '') . "\"\n";
    if (empty($config['email']['to_addresses'])) {
        $yaml .= "  to_addresses: []\n";
    } else {
        $yaml .= "  to_addresses:\n";
        foreach ($config['email']['to_addresses'] as $email) {
            $yaml .= "    - \"" . $yamlStr($email) . "\"\n";
        }
    }
    $yaml .= "  notify_on:\n";
    $yaml .= "    - port_down\n";
    $yaml .= "    - device_unreachable\n\n";
    
    // Logging — preserve the raw logging block from the original file to avoid
    // overwriting admin-tuned values (level, format, console, rotation settings).
    // Fall back to safe production defaults when no raw block exists yet.
    $loggingPreserved = false;
    if (!empty($config['_raw'])) {
        if (preg_match('/^(# Logging[^\n]*\n)?logging:\s*\n(?:[ \t][^\n]*\n?|[ \t]*\n)*/m', $config['_raw'], $lm)) {
            $yaml .= "\n" . rtrim($lm[0]) . "\n";
            $loggingPreserved = true;
        }
    }
    if (!$loggingPreserved) {
        $yaml .= "# Logging Configuration\n";
        $yaml .= "logging:\n";
        $yaml .= "  level: \"WARNING\"  # Sadece uyarı ve hatalar loglanır\n";
        $yaml .= "  format: \"text\"\n";
        $yaml .= "  file: \"logs/snmp_worker.log\"\n";
        $yaml .= "  max_bytes: 5242880\n";
        $yaml .= "  backup_count: 2\n";
        $yaml .= "  console: false\n";
    }
    
    // Preserve sections not managed by the admin UI (domain_server, system)
    // by extracting them verbatim from the original raw file content.
    if (!empty($config['_raw'])) {
        $raw = $config['_raw'];
        // Extract domain_server block (comment header + indented body)
        if (preg_match('/^(# Domain[^\n]*\n)?domain_server:\s*\n(?:[ \t][^\n]*\n?|[ \t]*\n)*/m', $raw, $m)) {
            $yaml .= "\n" . rtrim($m[0]) . "\n";
        }
        // Extract system block (comment header + indented body)
        if (preg_match('/^(# System[^\n]*\n)?system:\s*\n(?:[ \t][^\n]*\n?|[ \t]*\n)*/m', $raw, $m)) {
            $yaml .= "\n" . rtrim($m[0]) . "\n";
        }
    }
    
    return file_put_contents($filename, $yaml);
}

/**
 * Send a test email via SMTP using PHP socket streams.
 * Supports port 465 (implicit TLS) and port 587 (STARTTLS).
 * Returns ['success'=>bool, 'message'|'error'=>string].
 */
function sendTestEmailViaSmtp(string $host, int $port, string $user, string $pass,
                              string $from, string $to): array {
    $timeout = 15;
    $useImplicitTLS = ($port === 465);

    $ctx = stream_context_create([
        'ssl' => [
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
        ]
    ]);

    $proto  = $useImplicitTLS ? 'ssl' : 'tcp';
    $socket = @stream_socket_client("{$proto}://{$host}:{$port}", $errno, $errstr, $timeout,
                                    STREAM_CLIENT_CONNECT, $ctx);
    if (!$socket) {
        return ['success' => false, 'error' => "SMTP sunucusuna bağlanılamadı: {$errstr} ({$errno})"];
    }

    stream_set_timeout($socket, $timeout);

    // Helper: read full multi-line SMTP response, return last line
    $read = function() use ($socket) {
        $buf = '';
        while (($line = fgets($socket, 1024)) !== false) {
            $buf .= $line;
            if ($line[3] === ' ') break;   // 4th char ' ' = last continuation line
        }
        return trim($buf);
    };

    $greeting = $read();
    if (substr($greeting, 0, 3) !== '220') {
        fclose($socket);
        return ['success' => false, 'error' => "Beklenmeyen SMTP greeting: {$greeting}"];
    }

    // EHLO
    fwrite($socket, "EHLO localhost\r\n");
    $ehlo = $read();

    // STARTTLS upgrade for port 587
    if (!$useImplicitTLS && $port === 587) {
        fwrite($socket, "STARTTLS\r\n");
        $tls = $read();
        if (substr($tls, 0, 3) !== '220') {
            fclose($socket);
            return ['success' => false, 'error' => "STARTTLS reddedildi: {$tls}"];
        }
        stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        fwrite($socket, "EHLO localhost\r\n");
        $ehlo = $read();
    }

    // AUTH LOGIN
    fwrite($socket, "AUTH LOGIN\r\n");
    $r = $read();
    if (substr($r, 0, 3) !== '334') {
        fclose($socket);
        return ['success' => false, 'error' => "AUTH LOGIN desteklenmiyor: {$r}"];
    }
    fwrite($socket, base64_encode($user) . "\r\n");
    $r = $read();
    fwrite($socket, base64_encode($pass) . "\r\n");
    $r = $read();
    if (substr($r, 0, 3) !== '235') {
        fclose($socket);
        return ['success' => false, 'error' => "SMTP kimlik doğrulama başarısız: {$r} — kullanıcı adı/şifre kontrol edin"];
    }

    // Envelope
    fwrite($socket, "MAIL FROM:<{$from}>\r\n");    $read();
    fwrite($socket, "RCPT TO:<{$to}>\r\n");
    $r = $read();
    if (substr($r, 0, 3) !== '250') {
        fclose($socket);
        return ['success' => false, 'error' => "Alıcı reddedildi: {$r}"];
    }

    // Message
    fwrite($socket, "DATA\r\n");  $read();
    $date    = date('r');
    $subject = '=?UTF-8?B?' . base64_encode('CHAMADA Test maili başarıyla gönderildi!') . '?=';

    // Build CHAMADA dark-theme HTML body for test mail
    $testContent = "<p style='margin:0 0 14px;font-size:15px;font-weight:700;color:#10b981;'>✅ Test Maili Başarılı</p>"
        . "<p style='margin:4px 0;color:#c8d5e8;'>SNMP ağ izleme sisteminizin e-posta bildirimleri doğru yapılandırılmış.</p>"
        . "<p style='margin:12px 0 0;'><strong style='color:#8899bb;'>Tarih / Saat:</strong> " . date('d.m.Y H:i:s') . "</p>";

    // Inline the chamada_email_template function output since we're sending raw SMTP
    $logoSrc = 'data:image/png;base64,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';
    $logo = "<img src='{$logoSrc}' width='36' height='36' alt='CHAMADA' style='display:block;border:0;'>";
    $testHtml = "<!DOCTYPE html><html lang=\"tr\"><head><meta charset=\"UTF-8\"></head>"
        . "<body style=\"margin:0;padding:0;background:#0a0f1c;font-family:Arial,Helvetica,sans-serif;color:#c8d5e8;\">"
        . "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\"#0a0f1c\"><tr>"
        . "<td align=\"center\" style=\"padding:30px 10px;\">"
        . "<table width=\"620\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
        . "style=\"max-width:620px;width:100%;background:#111827;border-radius:10px;border:1px solid #1e2d4d;overflow:hidden;\">"
        . "<tr><td style=\"background:linear-gradient(135deg,#0d1527 0%,#1a2540 100%);padding:22px 28px;border-bottom:2px solid #d4a017;\">"
        . "<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>"
        . "<td style=\"vertical-align:middle;padding-right:14px;\">{$logo}</td>"
        . "<td style=\"vertical-align:middle;line-height:1.3;\">"
        . "<span style=\"display:block;font-size:20px;font-weight:900;color:#d4a017;letter-spacing:3px;\">CHAMADA</span>"
        . "<span style=\"display:block;font-size:12px;color:#8899bb;letter-spacing:1px;margin-top:2px;\">Test Maili</span>"
        . "</td></tr></table></td></tr>"
        . "<tr><td style=\"padding:28px;color:#c8d5e8;\">{$testContent}</td></tr>"
        . "<tr><td style=\"background:#070d1a;padding:14px 28px;border-top:1px solid #1e2d4d;text-align:center;\">"
        . "<span style=\"font-size:11px;color:#4a5568;\">CHAMADA Network Monitoring System &nbsp;|&nbsp; " . date('d.m.Y H:i:s') . "</span>"
        . "</td></tr></table></td></tr></table></body></html>";

    $boundary = md5(uniqid());
    $plainText = "CHAMADA Test Maili\r\n\r\nSNMP ağ izleme sisteminizin e-posta bildirimleri doğru yapılandırılmış.\r\nTarih: " . date('d.m.Y H:i:s') . "\r\n";
    $msg  = "From: {$from}\r\n"
          . "To: {$to}\r\n"
          . "Subject: {$subject}\r\n"
          . "Date: {$date}\r\n"
          . "MIME-Version: 1.0\r\n"
          . "Content-Type: multipart/alternative; boundary=\"{$boundary}\"\r\n"
          . "\r\n"
          . "--{$boundary}\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
          . $plainText . "\r\n"
          . "--{$boundary}\r\n"
          . "Content-Type: text/html; charset=UTF-8\r\n\r\n"
          . $testHtml . "\r\n"
          . "--{$boundary}--\r\n";
    fwrite($socket, $msg . "\r\n.\r\n");
    $r = $read();

    fwrite($socket, "QUIT\r\n");
    fclose($socket);

    if (substr($r, 0, 3) !== '250') {
        return ['success' => false, 'error' => "Mail gönderilemedi: {$r}"];
    }
    return ['success' => true, 'message' => "Test maili '{$to}' adresine başarıyla gönderildi!"];
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    try {
    // Load config - some actions don't require it
    $config = parseYamlConfig($configPath);
    
    // Actions that require config file
    $requiresConfig = ['add_switch', 'update_switch', 'delete_switch', 'update_telegram', 
                       'update_email', 'add_email', 'remove_email', 'update_snmp', 'update_polling', 'restart_service'];
    
    if (in_array($_POST['action'], $requiresConfig) && !$config) {
        echo json_encode(['success' => false, 'error' => 'Config dosyası okunamadı']);
        exit();
    }
    
    switch ($_POST['action']) {
        case 'add_switch':
            $config['switches'][] = [
                'name' => $_POST['name'],
                'host' => $_POST['host'],
                'vendor' => $_POST['vendor'] ?? 'cisco',
                'model' => $_POST['model'] ?? '',
                'enabled' => isset($_POST['enabled']) && $_POST['enabled'] === 'true',
                'description' => $_POST['description'] ?? ''
            ];
            saveYamlConfig($configPath, $config);
            echo json_encode(['success' => true, 'message' => 'Switch başarıyla eklendi']);
            break;
            
        case 'update_switch':
            $index = (int)$_POST['index'];
            if (isset($config['switches'][$index])) {
                $existing = $config['switches'][$index];
                $config['switches'][$index] = [
                    'name' => $_POST['name'],
                    'host' => $_POST['host'],
                    'vendor' => $_POST['vendor'] ?? 'cisco',
                    'model' => $_POST['model'] ?? '',
                    'enabled' => isset($_POST['enabled']) && $_POST['enabled'] === 'true',
                    'description' => $_POST['description'] ?? '',
                    // Preserve per-switch fields not exposed in the edit form
                    'engine_id' => $existing['engine_id'] ?? null,
                    'snmp_port' => $existing['snmp_port'] ?? null,
                    'trap_port' => $existing['trap_port'] ?? null,
                    'snmp_v3'   => $existing['snmp_v3']   ?? null,
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
            if (saveYamlConfig($configPath, $config) === false) {
                echo json_encode(['success' => false, 'error' => 'Yapılandırma dosyası yazılamadı (izin hatası)']);
            } else {
                echo json_encode(['success' => true, 'message' => 'Telegram ayarları güncellendi']);
            }
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
            if (saveYamlConfig($configPath, $config) === false) {
                echo json_encode(['success' => false, 'error' => 'Yapılandırma dosyası yazılamadı (izin hatası)']);
            } else {
                echo json_encode(['success' => true, 'message' => 'Email ayarları güncellendi']);
            }
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
            if (saveYamlConfig($configPath, $config) === false) {
                echo json_encode(['success' => false, 'error' => 'Yapılandırma dosyası yazılamadı (izin hatası)']);
            } else {
                echo json_encode(['success' => true, 'message' => 'SNMP ayarları güncellendi']);
            }
            break;
            
        case 'get_config':
            // Strip internal-only keys before sending to browser
            $configForClient = $config;
            unset($configForClient['_raw']);
            if (isset($configForClient['alarms']['_severity_routing_raw'])) {
                unset($configForClient['alarms']['_severity_routing_raw']);
            }
            echo json_encode(['success' => true, 'config' => $configForClient]);
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
                $alarm_type = $_POST['alarm_type'] ?? '';
                $severity = $_POST['severity'] ?? '';
                $telegram_enabled = isset($_POST['telegram_enabled']) && $_POST['telegram_enabled'] === 'true' ? 1 : 0;
                $email_enabled = isset($_POST['email_enabled']) && $_POST['email_enabled'] === 'true' ? 1 : 0;
                
                // Validate inputs
                if (empty($alarm_type)) {
                    echo json_encode(['success' => false, 'error' => 'Alarm tipi gerekli']);
                    break;
                }
                $valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
                if (!in_array($severity, $valid_severities)) {
                    echo json_encode(['success' => false, 'error' => 'Geçersiz severity seviyesi']);
                    break;
                }
                
                // Use UPSERT so the operation succeeds even if the row was never inserted
                // (e.g. migration ran before this alarm type was added to the defaults list).
                $upd = $conn->prepare("UPDATE alarm_severity_config SET severity=?, telegram_enabled=?, email_enabled=? WHERE alarm_type=?");
                if (!$upd) {
                    echo json_encode(['success' => false, 'error' => 'Sorgu hazırlama hatası: ' . $conn->error]);
                    break;
                }
                $upd->bind_param("siis", $severity, $telegram_enabled, $email_enabled, $alarm_type);
                $upd->execute();
                if ($conn->affected_rows == 0) {
                    $ins = $conn->prepare("INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled) VALUES (?, ?, ?, ?)");
                    $ins->bind_param("ssii", $alarm_type, $severity, $telegram_enabled, $email_enabled);
                    $ins->execute();
                    $ins->close();
                }
                $upd->close();
                
                if (true) {
                    echo json_encode(['success' => true, 'message' => 'Alarm seviyesi güncellendi']);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Güncelleme başarısız']);
                }
            } catch (\Throwable $e) {
                echo json_encode(['success' => false, 'error' => 'Hata: ' . $e->getMessage()]);
            }
            break;

        case 'get_alarm_user_email_config':
            // Get per-user email settings for an alarm type
            try {
                $alarm_type = $_POST['alarm_type'] ?? '';
                if (empty($alarm_type)) {
                    echo json_encode(['success' => false, 'error' => 'Alarm tipi gerekli']);
                    break;
                }
                // Get all active users with their per-alarm email setting
                $stmt = $conn->prepare(
                    "SELECT u.id, u.username, u.full_name, u.email, " .
                    "COALESCE(auc.email_enabled, 1) AS email_enabled " .
                    "FROM users u " .
                    "LEFT JOIN alarm_user_email_config auc ON auc.user_id = u.id AND auc.alarm_type = ? " .
                    "WHERE u.is_active = 1 AND u.email IS NOT NULL AND u.email != '' " .
                    "ORDER BY u.id ASC"
                );
                $stmt->bind_param('s', $alarm_type);
                $stmt->execute();
                $result = $stmt->get_result();
                $users = $result->fetch_all(MYSQLI_ASSOC);
                foreach ($users as &$u) {
                    $u['id'] = (int)$u['id'];
                    $u['email_enabled'] = (int)$u['email_enabled'];
                }
                unset($u);
                $stmt->close();
                echo json_encode(['success' => true, 'users' => $users]);
            } catch (\Throwable $e) {
                echo json_encode(['success' => false, 'error' => 'Hata: ' . $e->getMessage()]);
            }
            break;

        case 'save_alarm_user_email_config':
            // Save per-user email settings for an alarm type
            try {
                $alarm_type = $_POST['alarm_type'] ?? '';
                $user_ids = $_POST['user_ids'] ?? [];
                $email_enabled_arr = $_POST['email_enabled'] ?? [];
                if (empty($alarm_type)) {
                    echo json_encode(['success' => false, 'error' => 'Alarm tipi gerekli']);
                    break;
                }
                // Ensure table exists
                $conn->query(
                    "IF OBJECT_ID('dbo.alarm_user_email_config','U') IS NULL BEGIN " .
                    "CREATE TABLE alarm_user_email_config (" .
                    "alarm_type VARCHAR(100) NOT NULL, user_id INT NOT NULL, email_enabled BIT NOT NULL DEFAULT 1, " .
                    "CONSTRAINT PK_alarm_user_email_config PRIMARY KEY (alarm_type, user_id)" .
                    ") END"
                );
                foreach ($user_ids as $idx => $uid) {
                    $uid = (int)$uid;
                    $enabled = (int)(($email_enabled_arr[$idx] ?? '1') === '1' ? 1 : 0);
                    if (!$uid) continue;
                    $upd = $conn->prepare("UPDATE alarm_user_email_config SET email_enabled=? WHERE alarm_type=? AND user_id=?");
                    $upd->bind_param('isi', $enabled, $alarm_type, $uid);
                    $upd->execute();
                    if ($conn->affected_rows == 0) {
                        $ins = $conn->prepare("INSERT INTO alarm_user_email_config (alarm_type, user_id, email_enabled) VALUES (?, ?, ?)");
                        $ins->bind_param('sii', $alarm_type, $uid, $enabled);
                        $ins->execute();
                        $ins->close();
                    }
                    $upd->close();
                }
                echo json_encode(['success' => true, 'message' => 'Alıcı ayarları kaydedildi']);
            } catch (\Throwable $e) {
                echo json_encode(['success' => false, 'error' => 'Hata: ' . $e->getMessage()]);
            }
            break;

        case 'get_mail_log':
            try {
                $page = max(1, (int)($_POST['page'] ?? 1));
                $perPage = 50;
                $offset = ($page - 1) * $perPage;
                // Check if table exists
                $tableCheck = $conn->query("SELECT COUNT(*) as cnt FROM information_schema.tables WHERE table_name='email_log'");
                $tableExists = $tableCheck && ($row = $tableCheck->fetch_assoc()) && (int)$row['cnt'] > 0;
                if (!$tableExists) {
                    echo json_encode(['success' => true, 'logs' => [], 'total' => 0, 'page' => 1]);
                    break;
                }
                $countRes = $conn->query("SELECT COUNT(*) as cnt FROM email_log");
                $total = ($countRes && ($cr = $countRes->fetch_assoc())) ? (int)$cr['cnt'] : 0;
                $stmt = $conn->prepare(
                    "SELECT id, sent_at, subject, recipients, alarm_type, mail_type, status, error_msg " .
                    "FROM email_log ORDER BY sent_at DESC LIMIT ? OFFSET ?"
                );
                $stmt->bind_param('ii', $perPage, $offset);
                $stmt->execute();
                $result = $stmt->get_result();
                $logs = $result->fetch_all(MYSQLI_ASSOC);
                $stmt->close();
                echo json_encode(['success' => true, 'logs' => $logs, 'total' => $total, 'page' => $page, 'per_page' => $perPage]);
            } catch (\Throwable $e) {
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

        case 'test_email':
            // Test Email notification using current form values or saved config.
            // NOTE: use !empty() not ?? because ?? doesn't fall back on empty strings
            // (e.g. the browser sends an empty smtp_password when the field is blank).
            try {
                $smtpHost = !empty($_POST['smtp_host'])     ? $_POST['smtp_host']     : ($config['email']['smtp_host']     ?? '');
                $smtpPort = (int)(!empty($_POST['smtp_port']) ? $_POST['smtp_port'] : ($config['email']['smtp_port'] ?? 465));
                $smtpUser = !empty($_POST['smtp_user'])     ? $_POST['smtp_user']     : ($config['email']['smtp_user']     ?? '');
                $smtpPass = !empty($_POST['smtp_password']) ? $_POST['smtp_password'] : ($config['email']['smtp_password'] ?? '');
                $fromAddr = !empty($_POST['from_address'])  ? $_POST['from_address']  : ($config['email']['from_address']  ?? '');
                // First recipient, or fall back to the smtp_user itself
                $toArr    = !empty($_POST['to_addresses'])  ? $_POST['to_addresses']  : ($config['email']['to_addresses']  ?? []);
                $toAddr   = is_array($toArr) && !empty($toArr) ? array_values($toArr)[0] : $smtpUser;

                if (empty($smtpHost) || empty($smtpUser) || empty($smtpPass)) {
                    echo json_encode(['success' => false, 'error' => 'SMTP yapılandırması eksik (host, kullanıcı, şifre gerekli)']);
                    break;
                }
                if (empty($toAddr)) {
                    echo json_encode(['success' => false, 'error' => 'Alıcı e-posta adresi bulunamadı. Lütfen en az bir alıcı ekleyin.']);
                    break;
                }

                $result = sendTestEmailViaSmtp(
                    $smtpHost, $smtpPort, $smtpUser, $smtpPass,
                    $fromAddr ?: $smtpUser, $toAddr
                );
                echo json_encode($result);
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
                $config['switches'][] = [
                    'name' => $dbSwitch['name'],
                    'host' => $dbSwitch['ip'],
                    'vendor' => $dbSwitch['vendor'] ?: 'cisco',
                    'model' => $dbSwitch['model'] ?: '',
                    'enabled' => true,
                    'description' => $dbSwitch['description'] ?: ''
                ];
                
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
                        $config['switches'][] = [
                            'name' => $dbSwitch['name'],
                            'host' => $dbSwitch['ip'],
                            'vendor' => $dbSwitch['vendor'] ?: 'cisco',
                            'model' => $dbSwitch['model'] ?: '',
                            'enabled' => true,
                            'description' => $dbSwitch['description'] ?: ''
                        ];
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

        case 'get_uplink_ports':
            try {
                $stmt = $conn->prepare("
                    SELECT u.id, u.device_id, u.port_number, u.description, d.name as device_name
                    FROM snmp_uplink_ports u
                    JOIN snmp_devices d ON d.id = u.device_id
                    ORDER BY d.name, u.port_number
                ");
                $stmt->execute();
                $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
                echo json_encode(['success' => true, 'uplink_ports' => $rows]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            break;

        case 'add_uplink_port':
            try {
                $device_id   = intval($_POST['device_id'] ?? 0);
                $port_number = intval($_POST['port_number'] ?? 0);
                $description = trim($_POST['description'] ?? '');
                if ($device_id <= 0 || $port_number <= 0) {
                    echo json_encode(['success' => false, 'error' => 'Geçersiz parametreler']);
                    break;
                }
                $upd = $conn->prepare("UPDATE snmp_uplink_ports SET description=? WHERE device_id=? AND port_number=?");
                $upd->bind_param("sii", $description, $device_id, $port_number);
                $upd->execute();
                if ($conn->affected_rows == 0) {
                    $ins = $conn->prepare("INSERT INTO snmp_uplink_ports (device_id, port_number, description) VALUES (?, ?, ?)");
                    $ins->bind_param("iis", $device_id, $port_number, $description);
                    $ins->execute();
                    $ins->close();
                }
                $upd->close();
                echo json_encode(['success' => true, 'message' => 'Uplink port eklendi']);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            break;

        case 'delete_uplink_port':
            try {
                $id = intval($_POST['id'] ?? 0);
                if ($id <= 0) {
                    echo json_encode(['success' => false, 'error' => 'Geçersiz ID']);
                    break;
                }
                $stmt = $conn->prepare("DELETE FROM snmp_uplink_ports WHERE id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                echo json_encode(['success' => true, 'message' => 'Uplink port silindi']);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            break;

        case 'get_core_ports':
            try {
                $stmt = $conn->prepare("
                    SELECT c.id, c.device_id, c.port_number, c.core_switch_name, c.description, d.name as device_name
                    FROM snmp_core_ports c
                    JOIN snmp_devices d ON d.id = c.device_id
                    ORDER BY d.name, c.port_number
                ");
                $stmt->execute();
                $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
                echo json_encode(['success' => true, 'core_ports' => $rows]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            break;

        case 'add_core_port':
            try {
                $device_id        = intval($_POST['device_id'] ?? 0);
                $port_number      = intval($_POST['port_number'] ?? 0);
                $core_switch_name = trim($_POST['core_switch_name'] ?? '');
                $description      = trim($_POST['description'] ?? '');
                if ($device_id <= 0 || $port_number <= 0 || $core_switch_name === '') {
                    echo json_encode(['success' => false, 'error' => 'Geçersiz parametreler']);
                    break;
                }
                $upd = $conn->prepare("UPDATE snmp_core_ports SET core_switch_name=?, description=? WHERE device_id=? AND port_number=?");
                $upd->bind_param("ssii", $core_switch_name, $description, $device_id, $port_number);
                $upd->execute();
                if ($conn->affected_rows == 0) {
                    $ins = $conn->prepare("INSERT INTO snmp_core_ports (device_id, port_number, core_switch_name, description) VALUES (?, ?, ?, ?)");
                    $ins->bind_param("iiss", $device_id, $port_number, $core_switch_name, $description);
                    $ins->execute();
                    $ins->close();
                }
                $upd->close();
                echo json_encode(['success' => true, 'message' => 'Core port eklendi']);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            break;

        case 'delete_core_port':
            try {
                $id = intval($_POST['id'] ?? 0);
                if ($id <= 0) {
                    echo json_encode(['success' => false, 'error' => 'Geçersiz ID']);
                    break;
                }
                $stmt = $conn->prepare("DELETE FROM snmp_core_ports WHERE id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                echo json_encode(['success' => true, 'message' => 'Core port silindi']);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            break;

        case 'get_snmp_devices_list':
            try {
                $res = $conn->query("SELECT id, name, ip_address FROM snmp_devices WHERE enabled = 1 ORDER BY name");
                $devices = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
                echo json_encode(['success' => true, 'devices' => $devices]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            break;

        case 'service_status':
            // Detect OS and return service running status
            $running = false;
            $statusMsg = 'Bilinmiyor';
            if (PHP_OS_FAMILY === 'Windows') {
                exec('sc query SNMPWorker 2>&1', $out);
                $outStr = implode(' ', $out);
                $running = (strpos($outStr, 'RUNNING') !== false);
                $statusMsg = $running ? 'Çalışıyor' : 'Durduruldu';
            } else {
                // Linux: check for running python worker.py process
                exec('pgrep -f "worker.py" 2>&1', $pids);
                $running = count(array_filter($pids)) > 0;
                if (!$running) {
                    exec('systemctl is-active snmp-worker 2>&1', $svcOut);
                    $running = (trim(implode('', $svcOut)) === 'active');
                }
                $statusMsg = $running ? 'Çalışıyor' : 'Durduruldu';
            }
            echo json_encode(['success' => true, 'running' => $running, 'status' => $statusMsg]);
            break;

        case 'start_service':
            $ok = false;
            $msg = '';
            if (PHP_OS_FAMILY === 'Windows') {
                exec('sc start SNMPWorker 2>&1', $out, $rc);
                $outStr = implode(' ', $out);
                $ok = ($rc === 0 || strpos($outStr, 'START_PENDING') !== false || strpos($outStr, 'RUNNING') !== false);
                $msg = $ok ? 'Servis başlatıldı.' : 'Servis başlatılamadı. Lütfen Yönetici yetkisiyle XAMPP çalıştırın.';
            } else {
                exec('systemctl start snmp-worker 2>&1', $out, $rc);
                if ($rc !== 0) {
                    $workerPath = realpath(__DIR__ . '/../snmp_worker/worker.py');
                    if ($workerPath && strpos($workerPath, __DIR__) === 0) {
                        exec('nohup python3 ' . escapeshellarg($workerPath) . ' > /dev/null 2>&1 &', $out2, $rc);
                    }
                }
                $ok = ($rc === 0);
                $msg = $ok ? 'Servis başlatıldı.' : 'Servis başlatılamadı.';
            }
            echo json_encode(['success' => $ok, 'message' => $msg]);
            break;

        case 'stop_service':
            $ok = false;
            $msg = '';
            if (PHP_OS_FAMILY === 'Windows') {
                exec('sc stop SNMPWorker 2>&1', $out, $rc);
                $outStr = implode(' ', $out);
                $ok = ($rc === 0 || strpos($outStr, 'STOP_PENDING') !== false || strpos($outStr, 'STOPPED') !== false);
                $msg = $ok ? 'Servis durduruldu.' : 'Servis durdurulamadı. Lütfen Yönetici yetkisiyle XAMPP çalıştırın.';
            } else {
                exec('systemctl stop snmp-worker 2>&1', $out, $rc);
                if ($rc !== 0) {
                    exec('pkill -f "worker.py" 2>&1', $out2, $rc);
                }
                $ok = ($rc === 0);
                $msg = $ok ? 'Servis durduruldu.' : 'Servis durdurulamadı.';
            }
            echo json_encode(['success' => $ok, 'message' => $msg]);
            break;

        case 'update_polling':
            // Update polling interval and related settings in config.yml.
            // Validates the interval, patches the preserved _polling_raw block,
            // and saves the config.  The caller is expected to restart the worker.
            try {
                $interval = (int)($_POST['interval'] ?? 0);
                if ($interval < 15 || $interval > 600) {
                    echo json_encode(['success' => false, 'error' => 'Sorgu aralığı 15–600 saniye arasında olmalıdır']);
                    break;
                }
                // Optional related intervals — keep current value when not supplied
                $macInterval    = isset($_POST['mac_poll_interval'])    ? (int)$_POST['mac_poll_interval']    : null;
                $portInterval   = isset($_POST['port_poll_interval'])   ? (int)$_POST['port_poll_interval']   : null;
                $deviceInterval = isset($_POST['device_info_poll_interval']) ? (int)$_POST['device_info_poll_interval'] : null;

                $config['polling']['interval'] = $interval;
                if ($macInterval    !== null) $config['polling']['mac_poll_interval']         = max(15, $macInterval);
                if ($portInterval   !== null) $config['polling']['port_poll_interval']        = max(15, $portInterval);
                if ($deviceInterval !== null) $config['polling']['device_info_poll_interval'] = max(15, $deviceInterval);

                if (saveYamlConfig($configPath, $config) === false) {
                    echo json_encode(['success' => false, 'error' => 'Yapılandırma dosyası yazılamadı (izin hatası)']);
                } else {
                    echo json_encode([
                        'success'         => true,
                        'message'         => "Sorgu aralığı {$interval}s olarak kaydedildi",
                        'restart_required' => true,
                    ]);
                }
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => 'Hata: ' . $e->getMessage()]);
            }
            break;

        case 'restart_service':
            $ok  = false;
            $msg = '';
            if (PHP_OS_FAMILY === 'Windows') {
                exec('sc stop SNMPWorker 2>&1', $out1, $rc1);
                sleep(2);
                exec('sc start SNMPWorker 2>&1', $out2, $rc2);
                $outStr = implode(' ', array_merge($out1, $out2));
                $ok  = ($rc2 === 0 || strpos($outStr, 'RUNNING') !== false || strpos($outStr, 'START_PENDING') !== false);
                $msg = $ok ? 'Servis yeniden başlatıldı.' : 'Servis yeniden başlatılamadı. Lütfen Yönetici yetkisiyle XAMPP çalıştırın.';
            } else {
                exec('systemctl restart snmp-worker 2>&1', $out, $rc);
                if ($rc !== 0) {
                    // Fallback: kill + relaunch via nohup
                    exec('pkill -f "worker.py" 2>&1');
                    sleep(1);
                    $workerPath = realpath(__DIR__ . '/../snmp_worker/worker.py');
                    if ($workerPath && strpos($workerPath, realpath(__DIR__ . '/..')) === 0) {
                        exec('nohup python3 ' . escapeshellarg($workerPath) . ' > /dev/null 2>&1 &', $out2, $rc);
                    }
                }
                $ok  = ($rc === 0);
                $msg = $ok ? 'Servis yeniden başlatıldı.' : 'Servis yeniden başlatılamadı. Lütfen servisi elle yeniden başlatın.';
            }
            echo json_encode(['success' => $ok, 'message' => $msg]);
            break;

        default:
            echo json_encode(['success' => false, 'error' => 'Bilinmeyen işlem']);
    }
    } catch (Throwable $e) {
        error_log('admin_snmp_config POST error: ' . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Sunucu hatası: ' . $e->getMessage()]);
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
            padding: 16px;
            /* Optimize for 90% browser zoom: standard zoom (Chrome/Edge/Safari) */
            zoom: 1.11;
        }
        /* Firefox fallback for zoom (transform-based) */
        @supports not (zoom: 1) {
            body {
                transform: scale(1.11);
                transform-origin: 0 0;
                width: 90%;
            }
        }
        
        .container {
            max-width: 1500px;
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
            font-size: 22px;
            display: flex;
            align-items: center;
            gap: 12px;
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
            padding: 12px 16px;
            border: none;
            background: transparent;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-light);
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
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
            grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
            gap: 12px;
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
                <div id="serviceStatusBadge" style="display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:6px;background:rgba(15,23,42,0.8);border:1px solid rgba(56,189,248,0.3);font-size:13px;font-weight:600;">
                    <span id="serviceStatusDot" style="width:10px;height:10px;border-radius:50%;background:#6b7280;display:inline-block;"></span>
                    <span id="serviceStatusText" style="color:#94a3b8;">Kontrol ediliyor...</span>
                </div>
                <button id="btnStartService" onclick="startService()" class="btn btn-success" style="display:none;">
                    <i class="fas fa-play"></i> Servisi Başlat
                </button>
                <button id="btnStopService" onclick="stopService()" class="btn btn-danger" style="display:none;">
                    <i class="fas fa-stop"></i> Servisi Durdur
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
                <button class="tab-button" data-tab="email">
                    <i class="fas fa-envelope"></i> Email Ayarları
                </button>
                <button class="tab-button" data-tab="snmp">
                    <i class="fas fa-key"></i> SNMP Şifreleri
                </button>
                <button class="tab-button" data-tab="alarm-severity">
                    <i class="fas fa-exclamation-triangle"></i> Alarm Seviyeleri
                </button>
                <button class="tab-button" data-tab="mail-log">
                    <i class="fas fa-history"></i> Mail Geçmişi
                </button>
            </div>
            
            <!-- Switches Tab -->
            <div class="tab-content active" id="switches">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>SNMP Yapılandırmasındaki Switchler</h2>
                    <button onclick="openAddSwitchModal()" class="btn btn-primary">
                        <i class="fas fa-plus"></i> Yeni Switch Ekle
                    </button>
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
                
                <div style="background: rgba(24, 144, 255, 0.1); border: 1px solid rgba(24, 144, 255, 0.4); padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #1890ff;">
                    <p style="color: #93c5fd; margin: 0;">
                        <i class="fas fa-info-circle"></i>
                        <strong>Bilgi:</strong> Burada sistemde kayıtlı tüm switchler gösterilmektedir. Eksik bilgileri tamamlayıp SNMP yapılandırmasına ekleyebilirsiniz.
                    </p>
                </div>
                
                <div class="switch-list" id="dbSwitchList">
                    <p style="text-align: center; color: #718096;">Yükleniyor...</p>
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
                            <input type="text" id="smtp_host" name="smtp_host" placeholder="smtp.yandex.com.tr">
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
                        
                        <button type="button" onclick="testEmail()" class="btn btn-success" style="margin-left: 10px;">
                            <i class="fas fa-paper-plane"></i> Test Mail Gönder
                        </button>
                    </form>
                    
                    <div id="email-status" style="margin-top: 15px; padding: 10px; border-radius: 5px; display: none;"></div>
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

                <!-- Poll Interval Settings -->
                <div class="card" style="margin-top:20px;">
                    <h3><i class="fas fa-clock" style="color:var(--primary,#3b82f6);margin-right:8px;"></i>SW Sorgu Süresi (Poll Interval)</h3>
                    <p style="color:#94a3b8;font-size:13px;margin-bottom:16px;">
                        Her switch'in SNMP ile ne sıklıkla sorgulanacağını belirler. Düşük değer = daha hızlı alarm, daha yüksek SW/Server CPU yükü.
                    </p>
                    <form id="pollIntervalForm">
                        <div class="form-group">
                            <label>Hazır Seçenekler</label>
                            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
                                <button type="button" class="btn btn-secondary poll-preset" data-val="30"
                                        onclick="selectPollPreset(30)">
                                    <i class="fas fa-bolt"></i> 30s <small style="opacity:.7;">(Hızlı – Yüksek Yük)</small>
                                </button>
                                <button type="button" class="btn btn-primary poll-preset" data-val="60"
                                        onclick="selectPollPreset(60)">
                                    <i class="fas fa-check-circle"></i> 60s <small style="opacity:.7;">(Önerilen)</small>
                                </button>
                                <button type="button" class="btn btn-secondary poll-preset" data-val="120"
                                        onclick="selectPollPreset(120)">
                                    <i class="fas fa-leaf"></i> 120s <small style="opacity:.7;">(Ekonomik)</small>
                                </button>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="poll_interval_input">Manuel Değer (saniye)</label>
                            <input type="number" id="poll_interval_input" name="interval"
                                   min="15" max="600" step="5" style="max-width:160px;"
                                   placeholder="örn: 60">
                            <span style="margin-left:8px;color:#94a3b8;font-size:12px;">Min 15 s — Max 600 s</span>
                        </div>

                        <!-- Restart warning — visible after save -->
                        <div id="pollIntervalRestartWarning" style="display:none;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.45);border-left:4px solid #f59e0b;border-radius:8px;padding:14px 16px;margin-bottom:16px;">
                            <div style="display:flex;align-items:flex-start;gap:10px;">
                                <i class="fas fa-exclamation-triangle" style="color:#f59e0b;margin-top:2px;font-size:16px;flex-shrink:0;"></i>
                                <div>
                                    <strong style="color:#fbbf24;">Servis Yeniden Başlatılmalı</strong>
                                    <p style="color:#fde68a;margin:4px 0 10px;font-size:13px;">
                                        Yeni sorgu aralığı ayarlandı. Değişikliğin geçerli olması için SNMP Worker servisini yeniden başlatmanız gerekir.
                                    </p>
                                    <button type="button" onclick="restartService()" class="btn btn-warning" style="background:rgba(245,158,11,.25);border-color:rgba(245,158,11,.5);color:#fbbf24;">
                                        <i class="fas fa-redo"></i> Şimdi Yeniden Başlat
                                    </button>
                                </div>
                            </div>
                        </div>

                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Kaydet
                        </button>
                    </form>
                </div>
            </div>
            
            <!-- Alarm Severity Tab -->
            <div class="tab-content" id="alarm-severity">
                <div style="background: rgba(255, 193, 7, 0.1); border: 1px solid rgba(255, 193, 7, 0.4); padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #ffc107;">
                    <h3 style="color: #fbbf24; margin-bottom: 10px;"><i class="fas fa-info-circle"></i> Alarm Seviye Yönetimi</h3>
                    <p style="color: #fde68a; margin: 0;">
                        Her alarm tipi için severity seviyesi (CRITICAL/HIGH/MEDIUM/LOW) ve hangi kanallara bildirim gönderileceğini (Telegram/Email) buradan ayarlayabilirsiniz.
                    </p>
                </div>
                
                <div class="card">
                    <h3>Alarm Tipleri ve Seviyeler</h3>
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                            <thead>
                                <tr style="background: rgba(15, 23, 42, 0.8); border-bottom: 2px solid rgba(56, 189, 248, 0.3);">
                                    <th style="padding: 12px; text-align: left; color: #e2e8f0;">Alarm Tipi</th>
                                    <th style="padding: 12px; text-align: left; color: #e2e8f0;">Açıklama</th>
                                    <th style="padding: 12px; text-align: center; color: #e2e8f0;">Severity</th>
                                    <th style="padding: 12px; text-align: center; color: #e2e8f0;">
                                        <i class="fab fa-telegram" style="color: #0088cc;"></i> Telegram
                                    </th>
                                    <th style="padding: 12px; text-align: center; color: #e2e8f0;">
                                        <i class="fas fa-envelope" style="color: #d93025;"></i> Email
                                    </th>
                                    <th style="padding: 12px; text-align: center; color: #e2e8f0;">
                                        <i class="fas fa-users" style="color: #10b981;"></i> Alıcılar
                                    </th>
                                    <th style="padding: 12px; text-align: center; color: #e2e8f0;">İşlemler</th>
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

            <!-- Mail Log Tab -->
            <div class="tab-content" id="mail-log">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
                    <h2><i class="fas fa-history" style="color:#10b981;margin-right:8px;"></i> Mail Geçmişi</h2>
                    <button onclick="loadMailLog()" class="btn btn-secondary">
                        <i class="fas fa-sync"></i> Yenile
                    </button>
                </div>
                <div style="overflow-x:auto;">
                    <table style="width:100%;border-collapse:collapse;background:rgba(15,23,42,0.6);border-radius:8px;overflow:hidden;">
                        <thead>
                            <tr style="background:rgba(15,23,42,0.8);border-bottom:2px solid rgba(56,189,248,0.3);">
                                <th style="padding:10px 14px;text-align:left;color:#e2e8f0;">Gönderim Zamanı</th>
                                <th style="padding:10px 14px;text-align:left;color:#e2e8f0;">Konu</th>
                                <th style="padding:10px 14px;text-align:left;color:#e2e8f0;">Alıcılar</th>
                                <th style="padding:10px 14px;text-align:center;color:#e2e8f0;">Tip</th>
                                <th style="padding:10px 14px;text-align:center;color:#e2e8f0;">Alarm Tipi</th>
                                <th style="padding:10px 14px;text-align:center;color:#e2e8f0;">Durum</th>
                            </tr>
                        </thead>
                        <tbody id="mailLogTable">
                            <tr>
                                <td colspan="6" style="text-align:center;padding:30px;color:#94a3b8;">
                                    <i class="fas fa-spinner fa-spin"></i> Yükleniyor...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div id="mailLogPagination" style="display:flex;justify-content:flex-end;margin-top:12px;gap:8px;"></div>
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
                    <input type="text" id="switch_model" name="model" placeholder="örn: Catalyst 9300">
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

    <!-- Per-User Email Recipients Modal -->
    <div class="modal" id="recipientsModal" style="display:none;">
        <div class="modal-content" style="max-width:520px;">
            <h2 style="display:flex;align-items:center;gap:10px;">
                <i class="fas fa-users" style="color:#10b981;"></i>
                <span id="recipientsModalTitle">Email Alıcıları</span>
            </h2>
            <p style="color:#94a3b8;font-size:13px;margin:4px 0 16px;">
                Bu alarm tipi için hangi kullanıcıların e-posta alacağını ayarlayın.
                Email kanalı kapalıysa bu ayarların bir önemi yoktur.
            </p>
            <div id="recipientsList" style="max-height:360px;overflow-y:auto;"></div>
            <div style="display:flex;gap:10px;margin-top:20px;justify-content:flex-end;">
                <button onclick="saveRecipients()" class="btn btn-primary">
                    <i class="fas fa-save"></i> Kaydet
                </button>
                <button onclick="closeRecipientsModal()" class="btn btn-secondary">
                    <i class="fas fa-times"></i> İptal
                </button>
            </div>
        </div>
    </div>
    
    <script>
        // Strip internal-only keys that must not be embedded in the page HTML
        <?php
        $configForPage = $config;
        unset($configForPage['_raw']);
        if (isset($configForPage['alarms']['_severity_routing_raw'])) {
            unset($configForPage['alarms']['_severity_routing_raw']);
        }
        ?>
        let currentConfig = <?php echo json_encode($configForPage) ?: '{}'; ?>;
        
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                button.classList.add('active');
                document.getElementById(button.dataset.tab).classList.add('active');

                // Lazy-load mail log when tab is opened
                if (button.dataset.tab === 'mail-log') loadMailLog(1);
                // Lazy-load alarm severities when tab is opened
                if (button.dataset.tab === 'alarm-severity') loadAlarmSeverities();
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
                    <p><strong>IP:</strong> ***</p>
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
        
        // Test Email notification
        function testEmail() {
            const statusDiv = document.getElementById('email-status');
            statusDiv.style.display = 'block';
            statusDiv.style.background = '#edf2f7';
            statusDiv.style.color = '#2d3748';
            statusDiv.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Test maili gönderiliyor...';

            // Collect current form values (use saved config if fields empty)
            const toInputs = document.querySelectorAll('#emailList input[name="to_addresses[]"]');
            const toAddresses = [];
            toInputs.forEach(el => { if (el.value.trim()) toAddresses.push(el.value.trim()); });

            const params = new URLSearchParams({
                action:         'test_email',
                smtp_host:      document.getElementById('smtp_host').value,
                smtp_port:      document.getElementById('smtp_port').value,
                smtp_user:      document.getElementById('smtp_user').value,
                smtp_password:  document.getElementById('smtp_password').value,
                from_address:   document.getElementById('from_address').value,
            });
            toAddresses.forEach(addr => params.append('to_addresses[]', addr));

            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: params
            })
            .then(r => r.json())
            .then(result => {
                if (result.success) {
                    statusDiv.style.background = '#c6f6d5';
                    statusDiv.style.color = '#22543d';
                    statusDiv.innerHTML = '<i class="fas fa-check-circle"></i> ✅ ' + result.message;
                    showToast('Test maili gönderildi!', 'success');
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
            // Populate poll interval from polling config
            const interval = (currentConfig.polling && currentConfig.polling.interval) ? currentConfig.polling.interval : 60;
            document.getElementById('poll_interval_input').value = interval;
            // Highlight matching preset button
            document.querySelectorAll('.poll-preset').forEach(btn => {
                const isMatch = parseInt(btn.dataset.val) === parseInt(interval);
                btn.classList.toggle('btn-primary',   isMatch);
                btn.classList.toggle('btn-secondary', !isMatch);
            });
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
        
        // Navigate parent admin.php to the Switch Yönetimi section and open the edit modal
        function editSwitchInAdmin(id) {
            var p = window.parent;
            if (!p || !p.switchPage) { p.location.href = 'admin.php#switches'; return; }
            p.switchPage('switches');
            var doOpen = function() {
                var sw = ((p.adminData || {}).switches || []).find(function(s) { return s.id === id; });
                if (sw && p.openAdminSwitchModal) p.openAdminSwitchModal(sw);
            };
            if (p.adminData && p.adminData.switches) { doOpen(); }
            else { p.loadAdminData().then(doOpen).catch(function(){}); }
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
            
            fetch('admin_snmp_config.php', {
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
            })
            .catch(err => showToast('Bağlantı hatası: ' + err.message, 'error'));
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
            
            // Clear any previous auto-hide timer
            if (showToast._timer) clearTimeout(showToast._timer);
            showToast._timer = setTimeout(() => {
                toast.classList.remove('show');
            }, 5000);
        }
        
        // Reload config
        function reloadConfig() {
            fetch('admin_snmp_config.php?action=get_config', {
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
                    loadEmailConfig();
                    loadSNMPConfig();
                }
            })
            .catch(err => console.error('Config yenileme hatası:', err));
        }
        
        // Service control
        let _servicePolling = null;

        function checkServiceStatus() {
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'service_status'})
            })
            .then(r => r.json())
            .then(data => {
                const dot  = document.getElementById('serviceStatusDot');
                const txt  = document.getElementById('serviceStatusText');
                const btnStart = document.getElementById('btnStartService');
                const btnStop  = document.getElementById('btnStopService');
                if (data.success) {
                    if (data.running) {
                        dot.style.background = '#10b981';
                        dot.style.boxShadow = '0 0 6px #10b981';
                        txt.style.color = '#10b981';
                        txt.textContent = '● Çalışıyor';
                        if (btnStart) btnStart.style.display = 'none';
                        if (btnStop)  btnStop.style.display  = '';
                    } else {
                        dot.style.background = '#ef4444';
                        dot.style.boxShadow = '0 0 6px #ef4444';
                        txt.style.color = '#ef4444';
                        txt.textContent = '● Durduruldu';
                        if (btnStart) btnStart.style.display = '';
                        if (btnStop)  btnStop.style.display  = 'none';
                    }
                }
            })
            .catch(() => {
                const txt = document.getElementById('serviceStatusText');
                if (txt) { txt.textContent = '? Bilinmiyor'; txt.style.color = '#94a3b8'; }
            });
        }

        function startService() {
            const btn = document.getElementById('btnStartService');
            if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Başlatılıyor...'; }
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'start_service'})
            })
            .then(r => r.json())
            .then(data => {
                showToast(data.message || (data.success ? 'Servis başlatıldı.' : 'Başlatılamadı.'), data.success ? 'success' : 'error');
                setTimeout(checkServiceStatus, 1500);
            })
            .catch(e => showToast('Bağlantı hatası: ' + e.message, 'error'))
            .finally(() => { if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-play"></i> Servisi Başlat'; } });
        }

        function stopService() {
            if (!confirm('SNMP servisini durdurmak istediğinizden emin misiniz?')) return;
            const btn = document.getElementById('btnStopService');
            if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Durduruluyor...'; }
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'stop_service'})
            })
            .then(r => r.json())
            .then(data => {
                showToast(data.message || (data.success ? 'Servis durduruldu.' : 'Durdurulamadı.'), data.success ? 'success' : 'error');
                setTimeout(checkServiceStatus, 1500);
            })
            .catch(e => showToast('Bağlantı hatası: ' + e.message, 'error'))
            .finally(() => { if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-stop"></i> Servisi Durdur'; } });
        }
        
        // Form submissions
        document.getElementById('switchForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const index = formData.get('index');
            formData.set('action', index !== '' ? 'update_switch' : 'add_switch');
            formData.set('enabled', document.getElementById('switch_enabled').checked ? 'true' : 'false');
            
            fetch('admin_snmp_config.php', {
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
            })
            .catch(err => showToast('Bağlantı hatası: ' + err.message, 'error'));
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
            
            fetch('admin_snmp_config.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    reloadConfig();
                } else {
                    showToast(data.error || 'Email kaydetme hatası', 'error');
                }
            })
            .catch(err => showToast('Bağlantı hatası: ' + err.message, 'error'));
        });
        
        document.getElementById('snmpForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.set('action', 'update_snmp');
            
            fetch('admin_snmp_config.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    reloadConfig();
                } else {
                    showToast(data.error || 'SNMP kaydetme hatası', 'error');
                }
            })
            .catch(err => showToast('Bağlantı hatası: ' + err.message, 'error'));
        });

        // ── Poll Interval helpers ──────────────────────────────────────────────
        function selectPollPreset(val) {
            document.getElementById('poll_interval_input').value = val;
            document.querySelectorAll('.poll-preset').forEach(btn => {
                btn.classList.toggle('btn-primary',   parseInt(btn.dataset.val) === val);
                btn.classList.toggle('btn-secondary', parseInt(btn.dataset.val) !== val);
            });
        }

        function restartService() {
            const btn = event.target.closest('button');
            if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Yeniden başlatılıyor...'; }
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'restart_service'})
            })
            .then(r => r.json())
            .then(data => {
                showToast(data.message || (data.success ? 'Servis yeniden başlatıldı.' : 'Yeniden başlatılamadı.'), data.success ? 'success' : 'error');
                if (data.success) {
                    document.getElementById('pollIntervalRestartWarning').style.display = 'none';
                    if (typeof checkServiceStatus === 'function') setTimeout(checkServiceStatus, 2000);
                }
            })
            .catch(e => showToast('Bağlantı hatası: ' + e.message, 'error'))
            .finally(() => { if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-redo"></i> Şimdi Yeniden Başlat'; } });
        }

        document.getElementById('pollIntervalForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const interval = parseInt(document.getElementById('poll_interval_input').value);
            if (!interval || interval < 15 || interval > 600) {
                showToast('Geçerli bir değer girin (15–600 saniye)', 'error');
                return;
            }
            const formData = new FormData();
            formData.append('action', 'update_polling');
            formData.append('interval', interval);
            fetch('admin_snmp_config.php', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    if (data.restart_required) {
                        document.getElementById('pollIntervalRestartWarning').style.display = 'block';
                    }
                    reloadConfig();
                } else {
                    showToast(data.error || 'Kaydetme hatası', 'error');
                }
            })
            .catch(err => showToast('Bağlantı hatası: ' + err.message, 'error'));
        });
        
        // Load database switches
        function loadDbSwitches() {
            const container = document.getElementById('dbSwitchList');
            container.innerHTML = '<p style="text-align: center; color: #718096;">Yükleniyor...</p>';
            
            const formData = new FormData();
            formData.append('action', 'get_db_switches');
            
            fetch('admin_snmp_config.php', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                return response.text();
            })
            .then(text => {
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
                    <p><strong>IP:</strong> ${sw.ip ? '***' : '<span style="color: #f56565;">Eksik</span>'}</p>
                    <p><strong>Vendor:</strong> ${sw.vendor || '<span style="color: #cbd5e0;">Belirtilmemiş</span>'}</p>
                    ${sw.model ? `<p><strong>Model:</strong> ${sw.model}</p>` : ''}
                    ${sw.description ? `<p><strong>Açıklama:</strong> ${sw.description}</p>` : ''}
                    <p><strong>Port Sayısı:</strong> ${sw.ports || 'Belirtilmemiş'}</p>
                    ${!sw.ip ? '<p style="color: #f56565; font-size: 12px;"><i class="fas fa-exclamation-triangle"></i> IP adresi eksik! SNMP\'ye eklenemez.</p>' : ''}
                    <div class="actions">
                        ${sw.ip ? importButton : '<button class="btn btn-secondary" disabled>IP Eksik</button>'}
                        <a href="admin.php#switches" class="btn btn-primary" target="_parent"
                           onclick="event.preventDefault(); editSwitchInAdmin(${sw.id})">
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
            
            fetch('admin_snmp_config.php', {
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
            })
            .catch(err => showToast('Bağlantı hatası: ' + err.message, 'error'));
        }
        
        // Import all switches from database
        function importAllDbSwitches() {
            if (!confirm('Veritabanındaki TÜM switchleri SNMP yapılandırmasına eklemek istiyor musunuz? (Sadece SNMP\'de olmayan ve IP adresi olan switchler eklenecek)')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'import_all_from_db');
            
            fetch('admin_snmp_config.php', {
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
            })
            .catch(err => showToast('Bağlantı hatası: ' + err.message, 'error'));
        }
        
        // Initialize
        loadSwitches();
        loadEmailConfig();
        loadSNMPConfig();
        loadDbSwitches(); // Load database switches on start
        loadAlarmSeverities(); // Load alarm severities
        checkServiceStatus(); // Check service status on load
        // Poll service status every 15 seconds
        setInterval(checkServiceStatus, 15000);
        
        // Load alarm severity configuration
        function loadAlarmSeverities() {
            fetch('admin_snmp_config.php', {
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
        
        // Alarm type Turkish translations
        function getAlarmTypeTurkish(alarmType) {
            const types = {
                'device_unreachable': 'Cihaz Erişilemez',
                'multiple_ports_down': 'Birden Fazla Port Kapalı',
                'core_link_down': 'Core Uplink Kesildi',
                'mac_moved': 'MAC Taşındı',
                'port_down': 'Port Kapandı',
                'port_up': 'Port Açıldı',
                'vlan_changed': 'VLAN Değişti',
                'description_changed': 'Açıklama Değişti',
                'mac_added': 'MAC Eklendi',
                'snmp_error': 'SNMP Hatası'
            };
            return types[alarmType] || alarmType;
        }
        
        // Display alarm severities in table
        function displayAlarmSeverities(severities) {
            const table = document.getElementById('alarmSeverityTable');
            
            if (!severities || severities.length === 0) {
                table.innerHTML = `
                    <tr>
                        <td colspan="7" style="text-align: center; padding: 20px; color: #718096;">
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
                <tr style="border-bottom: 1px solid rgba(56, 189, 248, 0.15);">
                    <td style="padding: 12px; font-weight: 500; color: #e2e8f0;">
                        ${getAlarmTypeTurkish(item.alarm_type)}
                        <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">${item.alarm_type}</div>
                    </td>
                    <td style="padding: 12px; color: #a0aec0; font-size: 13px;">
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
                        <button onclick="openRecipientsModal('${item.alarm_type}')"
                                class="btn btn-secondary" style="padding: 6px 10px; font-size: 11px; background: rgba(16,185,129,.15); border-color: rgba(16,185,129,.4); color: #10b981;">
                            <i class="fas fa-users"></i> Ayarla
                        </button>
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
            
            fetch('admin_snmp_config.php', {
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

        // ── Per-user Email Recipients Modal ────────────────────────────
        let _currentRecipientsAlarmType = null;

        function openRecipientsModal(alarmType) {
            _currentRecipientsAlarmType = alarmType;
            document.getElementById('recipientsModalTitle').textContent =
                'Email Alıcıları — ' + getAlarmTypeTurkish(alarmType);
            document.getElementById('recipientsList').innerHTML =
                '<p style="text-align:center;color:#94a3b8;"><i class="fas fa-spinner fa-spin"></i> Yükleniyor...</p>';
            document.getElementById('recipientsModal').style.display = 'flex';

            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'get_alarm_user_email_config', alarm_type: alarmType})
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    document.getElementById('recipientsList').innerHTML =
                        `<p style="color:#e53e3e;">${data.error}</p>`;
                    return;
                }
                if (!data.users || data.users.length === 0) {
                    document.getElementById('recipientsList').innerHTML =
                        '<p style="color:#94a3b8;text-align:center;">E-posta adresi olan aktif kullanıcı bulunamadı.</p>';
                    return;
                }
                document.getElementById('recipientsList').innerHTML = data.users.map(u => `
                    <div style="display:flex;align-items:center;justify-content:space-between;
                                padding:10px 14px;border-bottom:1px solid #1e2d4d;">
                        <div>
                            <span style="font-weight:600;color:#e2e8f0;">${u.full_name || u.username}</span>
                            <span style="font-size:12px;color:#94a3b8;margin-left:8px;">${u.email}</span>
                        </div>
                        <label class="checkbox-switch">
                            <input type="checkbox" data-user-id="${u.id}" class="recipient-toggle"
                                   ${u.email_enabled ? 'checked' : ''}>
                            <span class="slider"></span>
                        </label>
                    </div>
                `).join('');
            })
            .catch(e => {
                document.getElementById('recipientsList').innerHTML =
                    `<p style="color:#e53e3e;">Yükleme hatası: ${e.message}</p>`;
            });
        }

        function closeRecipientsModal() {
            document.getElementById('recipientsModal').style.display = 'none';
            _currentRecipientsAlarmType = null;
        }

        function saveRecipients() {
            if (!_currentRecipientsAlarmType) return;
            const checkboxes = document.querySelectorAll('#recipientsList .recipient-toggle');
            const params = new URLSearchParams({
                action: 'save_alarm_user_email_config',
                alarm_type: _currentRecipientsAlarmType
            });
            checkboxes.forEach(cb => {
                params.append('user_ids[]', cb.dataset.userId);
                params.append('email_enabled[]', cb.checked ? '1' : '0');
            });
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: params
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message, 'success');
                    closeRecipientsModal();
                } else {
                    showToast(data.error, 'error');
                }
            })
            .catch(e => showToast('Kayıt hatası: ' + e.message, 'error'));
        }

        // Close modal when clicking outside
        document.getElementById('recipientsModal').addEventListener('click', function(e) {
            if (e.target === this) closeRecipientsModal();
        });

        // ── Mail Log ────────────────────────────────────────────────────
        let _mailLogPage = 1;

        function loadMailLog(page) {
            page = page || 1;
            _mailLogPage = page;
            const table = document.getElementById('mailLogTable');
            table.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;color:#94a3b8;"><i class="fas fa-spinner fa-spin"></i> Yükleniyor...</td></tr>';
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'get_mail_log', page: page})
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    table.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#e53e3e;">${data.error}</td></tr>`;
                    return;
                }
                if (!data.logs || data.logs.length === 0) {
                    table.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;color:#94a3b8;">Henüz gönderilmiş mail kaydı yok.</td></tr>';
                    document.getElementById('mailLogPagination').innerHTML = '';
                    return;
                }
                const statusColor = {sent: '#10b981', failed: '#e53e3e'};
                table.innerHTML = data.logs.map(l => `
                    <tr style="border-bottom:1px solid rgba(56,189,248,0.1);">
                        <td style="padding:10px 14px;color:#94a3b8;font-size:13px;white-space:nowrap;">${l.sent_at || '-'}</td>
                        <td style="padding:10px 14px;color:#e2e8f0;font-size:13px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${(l.subject||'').replace(/"/g,'&quot;')}">${l.subject || '-'}</td>
                        <td style="padding:10px 14px;color:#a0aec0;font-size:12px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${(l.recipients||'').replace(/"/g,'&quot;')}">${l.recipients || '-'}</td>
                        <td style="padding:10px 14px;text-align:center;font-size:12px;">
                            <span style="padding:2px 8px;border-radius:4px;background:rgba(16,185,129,0.15);color:#10b981;">${l.mail_type || '-'}</span>
                        </td>
                        <td style="padding:10px 14px;text-align:center;font-size:12px;color:#94a3b8;">${l.alarm_type || '-'}</td>
                        <td style="padding:10px 14px;text-align:center;">
                            <span style="padding:3px 10px;border-radius:4px;background:${(statusColor[l.status]||'#6b7280')}22;color:${statusColor[l.status]||'#6b7280'};font-size:12px;font-weight:600;">${l.status}</span>
                            ${l.error_msg ? `<div style="font-size:11px;color:#e53e3e;margin-top:2px;">${l.error_msg}</div>` : ''}
                        </td>
                    </tr>
                `).join('');
                // Pagination
                const totalPages = Math.ceil((data.total || 0) / (data.per_page || 50));
                let pagHtml = '';
                if (totalPages > 1) {
                    if (page > 1) pagHtml += `<button onclick="loadMailLog(${page-1})" class="btn btn-secondary" style="padding:5px 10px;font-size:12px;">‹ Önceki</button>`;
                    pagHtml += `<span style="color:#94a3b8;font-size:13px;padding:5px 8px;">${page} / ${totalPages}</span>`;
                    if (page < totalPages) pagHtml += `<button onclick="loadMailLog(${page+1})" class="btn btn-secondary" style="padding:5px 10px;font-size:12px;">Sonraki ›</button>`;
                }
                document.getElementById('mailLogPagination').innerHTML = pagHtml;
            })
            .catch(e => {
                table.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#e53e3e;">Yükleme hatası: ${e.message}</td></tr>`;
            });
        }

        // ── Uplink Ports ───────────────────────────────────────────────
        function loadSnmpDevicesList() {
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'get_snmp_devices_list'})
            })
            .then(r => r.json())
            .then(data => {
                const sel = document.getElementById('uplinkDeviceSelect');
                if (!sel) return;
                if (data.success && data.devices && data.devices.length > 0) {
                    sel.innerHTML = '<option value="">-- Switch Seçin --</option>' +
                        data.devices.map(d => `<option value="${d.id}">${d.name}</option>`).join('');
                } else {
                    sel.innerHTML = '<option value="">SNMP cihazı bulunamadı</option>';
                }
                // Also populate the core-ports device select with same device list
                populateCorePortDeviceSelect(data.success ? data.devices : []);
            })
            .catch(e => {
                const sel = document.getElementById('uplinkDeviceSelect');
                if (sel) sel.innerHTML = '<option value="">Yüklenemedi</option>';
                console.error('SNMP devices yükleme hatası:', e);
            });
        }

        function loadUplinkPorts() {
            const container = document.getElementById('uplinkPortsList');
            if (!container) return;
            container.innerHTML = '<p style="text-align:center;color:#718096;"><i class="fas fa-spinner fa-spin"></i> Yükleniyor...</p>';
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'get_uplink_ports'})
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    container.innerHTML = '<p style="color:#ef4444;">Hata: ' + (data.error || 'Bilinmeyen hata') + '</p>';
                    return;
                }
                const rows = data.uplink_ports || [];
                if (rows.length === 0) {
                    container.innerHTML = '<p style="text-align:center;color:#718096;">Henüz uplink port tanımlanmamış.</p>';
                    return;
                }
                container.innerHTML = `<table style="width:100%;border-collapse:collapse;">
                    <thead><tr style="background:rgba(15,23,42,.8);border-bottom:2px solid rgba(56,189,248,.3);">
                        <th style="padding:10px;text-align:left;color:#e2e8f0;">Switch</th>
                        <th style="padding:10px;text-align:center;color:#e2e8f0;">Port No</th>
                        <th style="padding:10px;text-align:left;color:#e2e8f0;">Açıklama</th>
                        <th style="padding:10px;text-align:center;color:#e2e8f0;">İşlem</th>
                    </tr></thead>
                    <tbody>` +
                    rows.map(r => `<tr style="border-bottom:1px solid #334155;">
                        <td style="padding:10px;color:#e2e8f0;">${r.device_name}</td>
                        <td style="padding:10px;text-align:center;"><span style="background:#0ea5e9;color:white;padding:3px 10px;border-radius:4px;font-weight:bold;">${r.port_number}</span></td>
                        <td style="padding:10px;color:#94a3b8;">${r.description || '-'}</td>
                        <td style="padding:10px;text-align:center;">
                            <button onclick="deleteUplinkPort(${r.id})" style="background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:6px;padding:5px 12px;cursor:pointer;">
                                <i class="fas fa-trash"></i> Sil
                            </button>
                        </td>
                    </tr>`).join('') +
                    '</tbody></table>';
            })
            .catch(e => {
                container.innerHTML = '<p style="color:#ef4444;">Yükleme hatası: ' + e.message + '</p>';
            });
        }

        function addUplinkPort() {
            const deviceId   = parseInt(document.getElementById('uplinkDeviceSelect')?.value || '0');
            const portNumber = parseInt(document.getElementById('uplinkPortNumber')?.value || '0');
            const description = document.getElementById('uplinkDescription')?.value?.trim() || '';
            if (!deviceId || !portNumber) {
                showToast('Switch ve port numarası zorunludur', 'error');
                return;
            }
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'add_uplink_port', device_id: deviceId, port_number: portNumber, description: description})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showToast('Uplink port eklendi', 'success');
                    document.getElementById('uplinkPortNumber').value = '';
                    document.getElementById('uplinkDescription').value = '';
                    loadUplinkPorts();
                } else {
                    showToast('Hata: ' + (data.error || 'Bilinmeyen hata'), 'error');
                }
            })
            .catch(e => showToast('Bağlantı hatası: ' + e.message, 'error'));
        }

        function deleteUplinkPort(id) {
            if (!confirm('Bu uplink portu silmek istediğinizden emin misiniz?')) return;
            fetch('admin_snmp_config.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({action: 'delete_uplink_port', id: id})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showToast('Uplink port silindi', 'success');
                    loadUplinkPorts();
                } else {
                    showToast('Hata: ' + (data.error || 'Bilinmeyen hata'), 'error');
                }
            })
            .catch(e => showToast('Bağlantı hatası: ' + e.message, 'error'));
        }

        // ── Core Ports ────────────────────────────────────────────────────
        // Populate the Core Port device dropdown from the same device list
        // used by the Uplink Port form.
        function populateCorePortDeviceSelect(devices) {
            const sel = document.getElementById('corePortDeviceId');
            if (!sel) return;
            sel.innerHTML = '<option value="">Switch seçin...</option>';
            (devices || []).forEach(d => {
                sel.innerHTML += `<option value="${d.id}">${escapeHtml(d.name)} (${escapeHtml(d.ip_address)})</option>`;
            });
        }

        function loadCorePorts() {
            const container = document.getElementById('corePortsList');
            if (!container) return;
            container.innerHTML = '<p style="text-align:center;color:#718096;"><i class="fas fa-spinner fa-spin"></i> Yükleniyor...</p>';
            fetch('admin_snmp_config.php', {
                method: 'POST',
                body: new URLSearchParams({action: 'get_core_ports'})
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) { container.innerHTML = `<p style="color:#f87171;">${escapeHtml(data.error||'Hata')}</p>`; return; }
                const rows = data.core_ports || [];
                if (!rows.length) {
                    container.innerHTML = '<p style="text-align:center;color:#718096;">Henüz core port eklenmemiş.</p>';
                    return;
                }
                let html = '<table style="width:100%;border-collapse:collapse;font-size:13px;">';
                html += '<thead><tr style="border-bottom:1px solid rgba(255,255,255,.1);">';
                html += '<th style="text-align:left;padding:8px;color:#94a3b8;">Switch</th>';
                html += '<th style="text-align:left;padding:8px;color:#94a3b8;">Port No</th>';
                html += '<th style="text-align:left;padding:8px;color:#94a3b8;">Core Switch</th>';
                html += '<th style="text-align:left;padding:8px;color:#94a3b8;">Açıklama</th>';
                html += '<th style="text-align:center;padding:8px;color:#94a3b8;">İşlem</th>';
                html += '</tr></thead><tbody>';
                rows.forEach(r => {
                    html += `<tr style="border-bottom:1px solid rgba(255,255,255,.05);">`;
                    html += `<td style="padding:8px;color:#e2e8f0;">${escapeHtml(r.device_name)}</td>`;
                    html += `<td style="padding:8px;color:#e2e8f0;">${r.port_number}</td>`;
                    html += `<td style="padding:8px;color:#fbbf24;">${escapeHtml(r.core_switch_name)}</td>`;
                    html += `<td style="padding:8px;color:#94a3b8;">${escapeHtml(r.description||'')}</td>`;
                    html += `<td style="padding:8px;text-align:center;">
                        <button onclick="deleteCorePort(${r.id})" style="background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:6px;padding:5px 12px;cursor:pointer;">
                            <i class="fas fa-trash"></i> Sil
                        </button></td>`;
                    html += '</tr>';
                });
                html += '</tbody></table>';
                container.innerHTML = html;
            })
            .catch(e => { container.innerHTML = `<p style="color:#f87171;">Hata: ${escapeHtml(e.message)}</p>`; });
        }

        function addCorePort() {
            const deviceId      = parseInt(document.getElementById('corePortDeviceId')?.value || '0');
            const portNumber    = parseInt(document.getElementById('corePortNumber')?.value || '0');
            const coreName      = (document.getElementById('corePortCoreName')?.value || '').trim();
            const description   = (document.getElementById('corePortDescription')?.value || '').trim();
            if (!deviceId || !portNumber || !coreName) {
                showToast('Switch, port numarası ve core switch adı zorunludur', 'error'); return;
            }
            fetch('admin_snmp_config.php', {
                method: 'POST',
                body: new URLSearchParams({action: 'add_core_port', device_id: deviceId, port_number: portNumber, core_switch_name: coreName, description: description})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message || 'Core port eklendi', 'success');
                    document.getElementById('corePortNumber').value = '';
                    document.getElementById('corePortCoreName').value = '';
                    document.getElementById('corePortDescription').value = '';
                    loadCorePorts();
                } else {
                    showToast('Hata: ' + (data.error || 'Bilinmeyen hata'), 'error');
                }
            })
            .catch(e => showToast('Bağlantı hatası: ' + e.message, 'error'));
        }

        function deleteCorePort(id) {
            if (!confirm('Bu core port kaydı silinsin mi?')) return;
            fetch('admin_snmp_config.php', {
                method: 'POST',
                body: new URLSearchParams({action: 'delete_core_port', id: id})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message || 'Core port silindi', 'success');
                    loadCorePorts();
                } else {
                    showToast('Hata: ' + (data.error || 'Bilinmeyen hata'), 'error');
                }
            })
            .catch(e => showToast('Bağlantı hatası: ' + e.message, 'error'));
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
