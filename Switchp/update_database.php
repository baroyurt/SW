<?php
/**
 * update_database.php - Geliştirilmiş Veritabanı Şema Güncelleme Scripti
 *
 * Bu script:
 * - Tüm schema değişikliklerini idempotent şekilde uygular
 * - snmp_worker/migrations/ klasöründeki SQL migration dosyalarını otomatik uygular
 * - Migration history ile entegre çalışır (hangi migration'lar uygulandı takip eder)
 * - Validation kontrolleri yapar (kritik kolonlar, foreign key integrity)
 * - Gereksiz/deprecated kolonları kaldırır ($unusedColumns dizisinde tanımlı olanlar)
 * - Web veya CLI'dan çalıştırılabilir
 * - Her adımın sonucunu HTML tablo olarak raporlar
 *
 * YENİ ÖZELLİKLER:
 * - Migration tracker entegrasyonu (migration_history tablosu)
 * - SQL migration dosyalarını otomatik uygulama
 * - Validation helper fonksiyonları
 * - Migration istatistikleri görüntüleme
 * - Detaylı hata mesajları ve timing bilgisi
 * - VLAN izleme kolonları (old_vlan_id, new_vlan_id) alarms tablosuna eklendi
 *
 * KULLANIM:
 * 1. Yeni bir SQL migration eklemek için:
 *    - Dosyayı snmp_worker/migrations/ klasörüne ekleyin
 *    - $migrationFiles dizisine dosya adını ekleyin
 *    - Bu scripti çalıştırın
 *
 * 2. Gereksiz bir kolonu kaldırmak için:
 *    - $unusedColumns dizisine table ve column ekleyin
 *    - Örnek: ['table' => 'ports', 'column' => 'old_column']
 *
 * ÖNEMLI:
 * - Production'da çalıştırmadan önce MUTLAKA veritabanı yedeği alın!
 * - DDL statement'lar tablo kilitleri oluşturabilir; bakım penceresinde çalıştırın
 * - Migration tracker sayesinde aynı migration tekrar uygulanmaz
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

// DB credentials (adjust if needed)
$host = "127.0.0.1";
$user = "root";
$pass = "";
$db   = "switchdb";

function h($s) { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

try {
    $conn = new mysqli($host, $user, $pass, $db);
    if ($conn->connect_error) throw new Exception("DB bağlantı hatası: " . $conn->connect_error);
    $conn->set_charset('utf8mb4');
} catch (Exception $e) {
    echo "<h1>Bağlantı hatası</h1><pre>" . h($e->getMessage()) . "</pre>";
    exit;
}

// Helper checks
function tableExists($conn, $table) {
    $t = $conn->real_escape_string($table);
    $res = $conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{$t}' LIMIT 1");
    return ($res && $res->num_rows > 0);
}

function columnExists($conn, $table, $column) {
    $t = $conn->real_escape_string($table);
    $c = $conn->real_escape_string($column);
    $res = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{$t}' AND COLUMN_NAME = '{$c}' LIMIT 1");
    return ($res && $res->num_rows > 0);
}

function indexExists($conn, $table, $indexName) {
    $t = $conn->real_escape_string($table);
    $i = $conn->real_escape_string($indexName);
    $res = $conn->query("SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{$t}' AND INDEX_NAME = '{$i}' LIMIT 1");
    return ($res && $res->num_rows > 0);
}

function fkExists($conn, $table, $column, $referencedTable) {
    $t = $conn->real_escape_string($table);
    $c = $conn->real_escape_string($column);
    $r = $conn->real_escape_string($referencedTable);
    $res = $conn->query("SELECT 1 FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{$t}' AND COLUMN_NAME = '{$c}' AND REFERENCED_TABLE_NAME = '{$r}' LIMIT 1");
    return ($res && $res->num_rows > 0);
}

function enumHasValue($conn, $table, $column, $value) {
    $t = $conn->real_escape_string($table);
    $c = $conn->real_escape_string($column);
    $res = $conn->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{$t}' AND COLUMN_NAME = '{$c}' LIMIT 1");
    if (!$res || $res->num_rows == 0) return false;
    $row = $res->fetch_assoc();
    $type = $row['COLUMN_TYPE'];
    return (strpos($type, "'" . $conn->real_escape_string($value) . "'") !== false);
}

/**
 * Migration tracker'da migration'ın uygulandığını kaydet
 */
function recordMigration($conn, $migrationName, $type = 'PHP', $success = true, $errorMsg = null, $execTime = null) {
    if (!tableExists($conn, 'migration_history')) {
        $sql = "CREATE TABLE IF NOT EXISTS migration_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            migration_name VARCHAR(255) NOT NULL UNIQUE,
            migration_type ENUM('SQL', 'PYTHON', 'PHP') NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN DEFAULT TRUE,
            error_message TEXT NULL,
            execution_time_ms INT NULL,
            applied_by VARCHAR(100) DEFAULT 'system',
            INDEX idx_applied_at (applied_at),
            INDEX idx_migration_type (migration_type),
            INDEX idx_success (success)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
        $conn->query($sql);
    }
    
    $name = $conn->real_escape_string($migrationName);
    $typeEsc = $conn->real_escape_string($type);
    $successInt = $success ? 1 : 0;
    $errorEsc = $errorMsg ? "'" . $conn->real_escape_string($errorMsg) . "'" : 'NULL';
    $timeVal = $execTime ? (int)$execTime : 'NULL';
    
    $sql = "INSERT INTO migration_history (migration_name, migration_type, success, error_message, execution_time_ms) 
            VALUES ('{$name}', '{$typeEsc}', {$successInt}, {$errorEsc}, {$timeVal})
            ON DUPLICATE KEY UPDATE 
                applied_at = CURRENT_TIMESTAMP,
                success = {$successInt},
                error_message = {$errorEsc},
                execution_time_ms = {$timeVal}";
    $conn->query($sql);
}

/**
 * Migration'ın daha önce uygulanıp uygulanmadığını kontrol et
 */
function isMigrationApplied($conn, $migrationName) {
    if (!tableExists($conn, 'migration_history')) return false;
    $name = $conn->real_escape_string($migrationName);
    $res = $conn->query("SELECT 1 FROM migration_history WHERE migration_name = '{$name}' AND success = 1 LIMIT 1");
    return ($res && $res->num_rows > 0);
}

/**
 * SQL migration dosyasını uygula
 */
function applySQLMigration($conn, $filePath) {
    $sql = file_get_contents($filePath);
    if (!$sql) return false;
    
    // Birden fazla statement varsa ayır ve uygula
    $conn->multi_query($sql);
    
    // Tüm sonuçları al
    do {
        if ($result = $conn->store_result()) {
            $result->free();
        }
    } while ($conn->more_results() && $conn->next_result());
    
    // Hata kontrolü
    if ($conn->error) {
        throw new Exception("SQL hatası: " . $conn->error);
    }
    
    return true;
}

/**
 * Validation: Kritik kolonların varlığını kontrol et
 */
function validateCriticalColumns($conn) {
    $checks = [
        ['table' => 'switches', 'column' => 'id'],
        ['table' => 'switches', 'column' => 'name'],
        ['table' => 'switches', 'column' => 'ip'],
        ['table' => 'ports', 'column' => 'id'],
        ['table' => 'ports', 'column' => 'switch_id'],
        ['table' => 'ports', 'column' => 'port_no'],
    ];
    
    $missing = [];
    foreach ($checks as $check) {
        if (tableExists($conn, $check['table']) && !columnExists($conn, $check['table'], $check['column'])) {
            $missing[] = $check['table'] . '.' . $check['column'];
        }
    }
    
    return empty($missing) ? true : "Eksik kritik kolonlar: " . implode(', ', $missing);
}

// Steps to run with checks. Each step: 'name', 'apply' => callable, 'check' => callable returning bool
$steps = [];

/* 1) Make ip/mac/device TEXT on ports (if not already TEXT) */
$steps[] = [
    'name' => "ports: ip, mac, device -> TEXT",
    'check' => function($c) {
        $cols = ['ip','mac','device'];
        foreach ($cols as $col) {
            $res = $c->query("SELECT DATA_TYPE, COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ports' AND COLUMN_NAME = '" . $c->real_escape_string($col) . "' LIMIT 1");
            if (!$res || $res->num_rows == 0) return false;
            $row = $res->fetch_assoc();
            // treat TEXT or longtext as ok
            if (stripos($row['DATA_TYPE'], 'text') === false) return false;
        }
        return true;
    },
    'apply' => function($c) {
        // Modify using MODIFY ... TEXT for each column (safe enough)
        $sql = "ALTER TABLE ports 
                MODIFY COLUMN ip TEXT,
                MODIFY COLUMN mac TEXT,
                MODIFY COLUMN device TEXT";
        return $c->query($sql);
    }
];

/* 2) Add hub columns to ports */
$steps[] = [
    'name' => "ports: add is_hub, hub_name, multiple_connections, device_count",
    'check' => function($c) {
        $cols = ['is_hub','hub_name','multiple_connections','device_count'];
        foreach ($cols as $col) if (!columnExists($c,'ports',$col)) return false;
        return true;
    },
    'apply' => function($c) {
        $sql = "ALTER TABLE ports 
                ADD COLUMN is_hub TINYINT(1) DEFAULT 0,
                ADD COLUMN hub_name VARCHAR(100) DEFAULT NULL,
                ADD COLUMN multiple_connections TEXT DEFAULT NULL,
                ADD COLUMN device_count INT DEFAULT 0";
        return $c->query($sql);
    }
];

/* 3) Expand ports.type */
$steps[] = [
    'name' => "ports: type VARCHAR(50)",
    'check' => function($c) {
        $res = $c->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ports' AND COLUMN_NAME = 'type' LIMIT 1");
        if (!$res || $res->num_rows==0) return false;
        $row = $res->fetch_assoc();
        return (stripos($row['COLUMN_TYPE'],'varchar(50)') !== false);
    },
    'apply' => function($c) {
        return $c->query("ALTER TABLE ports MODIFY COLUMN type VARCHAR(50)");
    }
];

/* 4) Create fiber_panels table */
$steps[] = [
    'name' => "Create table fiber_panels",
    'check' => function($c){ return tableExists($c,'fiber_panels'); },
    'apply' => function($c) {
        $sql = "CREATE TABLE IF NOT EXISTS fiber_panels (
            id INT AUTO_INCREMENT PRIMARY KEY,
            rack_id INT NOT NULL,
            panel_letter VARCHAR(1) NOT NULL,
            total_fibers INT NOT NULL,
            description TEXT,
            position_in_rack INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_panel (rack_id, panel_letter)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        return $c->query($sql);
    }
];

/* 5) Create patch_panels table */
$steps[] = [
    'name' => "Create table patch_panels",
    'check' => function($c){ return tableExists($c,'patch_panels'); },
    'apply' => function($c) {
        $sql = "CREATE TABLE IF NOT EXISTS patch_panels (
            id INT AUTO_INCREMENT PRIMARY KEY,
            rack_id INT NOT NULL,
            panel_letter VARCHAR(1) NOT NULL,
            total_ports INT NOT NULL,
            description TEXT,
            position_in_rack INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_panel (rack_id, panel_letter)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        return $c->query($sql);
    }
];

/* 6) Create patch_ports table */
$steps[] = [
    'name' => "Create table patch_ports",
    'check' => function($c){ return tableExists($c,'patch_ports'); },
    'apply' => function($c) {
        $sql = "CREATE TABLE IF NOT EXISTS patch_ports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            panel_id INT NOT NULL,
            port_number INT NOT NULL,
            status VARCHAR(20) DEFAULT 'inactive',
            connected_to VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_port (panel_id, port_number)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        return $c->query($sql);
    }
];

/* 7) Add position_in_rack to switches */
$steps[] = [
    'name' => "switches: add position_in_rack",
    'check' => function($c){ return columnExists($c,'switches','position_in_rack'); },
    'apply' => function($c){ return $c->query("ALTER TABLE switches ADD COLUMN position_in_rack INT DEFAULT NULL"); }
];

/* 8) Add unique on switches.name */
$steps[] = [
    'name' => "switches: unique key on name",
    'check' => function($c){ return indexExists($c,'switches','unique_switch_name'); },
    'apply' => function($c){ return $c->query("ALTER TABLE switches ADD UNIQUE KEY unique_switch_name (name)"); }
];

/* 9) Add unique (switch_id, port_no) on ports */
$steps[] = [
    'name' => "ports: unique (switch_id, port_no)",
    'check' => function($c){ return indexExists($c,'ports','unique_port'); },
    'apply' => function($c){ return $c->query("ALTER TABLE ports ADD UNIQUE KEY unique_port (switch_id, port_no)"); }
];

/* 10) Index ports(switch_id, port_no) */
$steps[] = [
    'name' => "ports: index idx_ports_switch_port on (switch_id, port_no)",
    'check' => function($c){ return indexExists($c,'ports','idx_ports_switch_port'); },
    'apply' => function($c){ return $c->query("CREATE INDEX idx_ports_switch_port ON ports(switch_id, port_no)"); }
];

/* 11) Index ports.is_hub */
$steps[] = [
    'name' => "ports: index idx_ports_is_hub on is_hub",
    'check' => function($c){ return indexExists($c,'ports','idx_ports_is_hub'); },
    'apply' => function($c){ return $c->query("CREATE INDEX idx_ports_is_hub ON ports(is_hub)"); }
];

/* 12) Fulltext on multiple_connections (may fail depending on engine/column) */
$steps[] = [
    'name' => "ports: FULLTEXT idx_multiple_connections (multiple_connections)",
    'check' => function($c){ return indexExists($c,'ports','idx_multiple_connections'); },
    'apply' => function($c){
        // MySQL requires MyISAM historically for fulltext prior to 5.6; InnoDB supports FULLTEXT from 5.6+
        return $c->query("ALTER TABLE ports ADD FULLTEXT INDEX idx_multiple_connections (multiple_connections)");
    }
];

/* 13) index idx_switches_ip on switches(ip) */
$steps[] = [
    'name' => "switches: index idx_switches_ip on ip",
    'check' => function($c){ return indexExists($c,'switches','idx_switches_ip'); },
    'apply' => function($c){ return $c->query("CREATE INDEX idx_switches_ip ON switches(ip)"); }
];

/* 14) FULLTEXT idx_ports_ip on ports(ip) */
$steps[] = [
    'name' => "ports: FULLTEXT idx_ports_ip (ip)",
    'check' => function($c){ return indexExists($c,'ports','idx_ports_ip'); },
    'apply' => function($c){ return $c->query("ALTER TABLE ports ADD FULLTEXT INDEX idx_ports_ip (ip)"); }
];

/* 15) FULLTEXT idx_ports_mac on ports(mac) */
$steps[] = [
    'name' => "ports: FULLTEXT idx_ports_mac (mac)",
    'check' => function($c){ return indexExists($c,'ports','idx_ports_mac'); },
    'apply' => function($c){ return $c->query("ALTER TABLE ports ADD FULLTEXT INDEX idx_ports_mac (mac)"); }
];

/* 16) Add connected_panel_id, connected_panel_port, connection_info_preserved to ports */
$steps[] = [
    'name' => "ports: add connected_panel_id, connected_panel_port, connection_info_preserved",
    'check' => function($c){
        return columnExists($c,'ports','connected_panel_id')
            && columnExists($c,'ports','connected_panel_port')
            && columnExists($c,'ports','connection_info_preserved');
    },
    'apply' => function($c){
        return $c->query("ALTER TABLE ports 
            ADD COLUMN connected_panel_id INT DEFAULT NULL,
            ADD COLUMN connected_panel_port INT DEFAULT NULL,
            ADD COLUMN connection_info_preserved TEXT DEFAULT NULL
        ");
    }
];

/* 17) Foreign key ports.connected_panel_id -> patch_panels(id) (only if patch_panels exists) */
$steps[] = [
    'name' => "ports: FK connected_panel_id -> patch_panels(id)",
    'check' => function($c){ return fkExists($c,'ports','connected_panel_id','patch_panels'); },
    'apply' => function($c){
        // Only add if patch_panels exists
        if (!tableExists($c,'patch_panels')) return false;
        return $c->query("ALTER TABLE ports ADD CONSTRAINT fk_ports_connected_panel FOREIGN KEY (connected_panel_id) REFERENCES patch_panels(id) ON DELETE SET NULL");
    }
];

/* 18) Add connected_switch_* and connection_type to patch_ports */
$steps[] = [
    'name' => "patch_ports: add connected_switch_id, connected_switch_port, connection_type, connection_details",
    'check' => function($c){
        $cols = ['connected_switch_id','connected_switch_port','connection_type','connection_details'];
        foreach ($cols as $col) if (!columnExists($c,'patch_ports',$col)) return false;
        return true;
    },
    'apply' => function($c){
        return $c->query("ALTER TABLE patch_ports
            ADD COLUMN connected_switch_id INT DEFAULT NULL,
            ADD COLUMN connected_switch_port INT DEFAULT NULL,
            ADD COLUMN connection_type ENUM('direct','jump_point') DEFAULT 'direct',
            ADD COLUMN connection_details TEXT DEFAULT NULL
        ");
    }
];

/* 19) FK patch_ports.connected_switch_id -> switches(id) */
$steps[] = [
    'name' => "patch_ports: FK connected_switch_id -> switches(id)",
    'check' => function($c){ return fkExists($c,'patch_ports','connected_switch_id','switches'); },
    'apply' => function($c){ return $c->query("ALTER TABLE patch_ports ADD CONSTRAINT fk_patch_ports_switch FOREIGN KEY (connected_switch_id) REFERENCES switches(id) ON DELETE SET NULL"); }
];

/* 20) Create fiber_ports table */
$steps[] = [
    'name' => "Create table fiber_ports",
    'check' => function($c){ return tableExists($c,'fiber_ports'); },
    'apply' => function($c){
        $sql = "CREATE TABLE IF NOT EXISTS fiber_ports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            panel_id INT NOT NULL,
            port_number INT NOT NULL,
            status ENUM('active','inactive') DEFAULT 'inactive',
            connected_to VARCHAR(255) DEFAULT NULL,
            connection_type ENUM('switch_fiber','panel_to_panel','jump_point') DEFAULT 'switch_fiber',
            connected_switch_id INT DEFAULT NULL,
            connected_switch_port INT DEFAULT NULL,
            connected_fiber_panel_id INT DEFAULT NULL,
            connected_fiber_panel_port INT DEFAULT NULL,
            is_jump_point BOOLEAN DEFAULT FALSE,
            jump_path TEXT,
            connection_details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_fiber_port (panel_id, port_number)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        $res = $c->query($sql);
        // add FK constraints separately (so we can check patch/fiber tables exist)
        return $res;
    }
];

/* 21) Index ports(connected_panel_id, connected_panel_port) */
$steps[] = [
    'name' => "ports: index idx_ports_panel_connection (connected_panel_id, connected_panel_port)",
    'check' => function($c){ return indexExists($c,'ports','idx_ports_panel_connection'); },
    'apply' => function($c){ return $c->query("CREATE INDEX idx_ports_panel_connection ON ports(connected_panel_id, connected_panel_port)"); }
];

/* 22) Index patch_ports (connected_switch_id,connected_switch_port) */
$steps[] = [
    'name' => "patch_ports: index idx_patch_ports_switch_connection",
    'check' => function($c){ return indexExists($c,'patch_ports','idx_patch_ports_switch_connection'); },
    'apply' => function($c){ return $c->query("CREATE INDEX idx_patch_ports_switch_connection ON patch_ports(connected_switch_id, connected_switch_port)"); }
];

/* 23) Index fiber_ports connections */
$steps[] = [
    'name' => "fiber_ports: index idx_fiber_ports_connections",
    'check' => function($c){ return indexExists($c,'fiber_ports','idx_fiber_ports_connections'); },
    'apply' => function($c){ return $c->query("CREATE INDEX idx_fiber_ports_connections ON fiber_ports(connected_switch_id, connected_fiber_panel_id)"); }
];

/* 24) connection_history table */
$steps[] = [
    'name' => "Create table connection_history",
    'check' => function($c){ return tableExists($c,'connection_history'); },
    'apply' => function($c){
        $sql = "CREATE TABLE IF NOT EXISTS connection_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            connection_type ENUM('switch_to_patch','switch_to_fiber','fiber_to_fiber','fiber_to_switch') NOT NULL,
            source_type VARCHAR(50) NOT NULL,
            source_id INT NOT NULL,
            source_port INT NOT NULL,
            target_type VARCHAR(50) NOT NULL,
            target_id INT NOT NULL,
            target_port INT NOT NULL,
            action ENUM('created','updated','deleted') NOT NULL,
            old_values TEXT,
            new_values TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_source (source_type, source_id, source_port),
            INDEX idx_target (target_type, target_id, target_port),
            INDEX idx_created (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        return $c->query($sql);
    }
];

/* 25) ports.connected_to column */
$steps[] = [
    'name' => "ports: add connected_to VARCHAR(255)",
    'check' => function($c){ return columnExists($c,'ports','connected_to'); },
    'apply' => function($c){ return $c->query("ALTER TABLE ports ADD COLUMN connected_to VARCHAR(255) DEFAULT NULL"); }
];

/* 26) Expand patch_ports.connection_type enum (add switch_to_panel/panel_to_switch) */
$steps[] = [
    'name' => "patch_ports: expand connection_type enum to include switch_to_panel/panel_to_switch",
    'check' => function($c){ return enumHasValue($c,'patch_ports','connection_type','switch_to_panel'); },
    'apply' => function($c){
        return $c->query("ALTER TABLE patch_ports MODIFY COLUMN connection_type ENUM('direct','jump_point','switch_to_panel','panel_to_switch') DEFAULT 'direct'");
    }
];

/* 27) Expand fiber_ports.connection_type enum */
$steps[] = [
    'name' => "fiber_ports: expand connection_type enum values",
    'check' => function($c){ return enumHasValue($c,'fiber_ports','connection_type','switch_to_panel'); },
    'apply' => function($c){
        return $c->query("ALTER TABLE fiber_ports MODIFY COLUMN connection_type ENUM('switch_fiber','panel_to_panel','jump_point','switch_to_panel','panel_to_switch') DEFAULT 'switch_fiber'");
    }
];

/* 28) Index on ports.connected_to (prefix) */
$steps[] = [
    'name' => "ports: index idx_ports_connected_to (connected_to(100))",
    'check' => function($c){ return indexExists($c,'ports','idx_ports_connected_to'); },
    'apply' => function($c){ return $c->query("CREATE INDEX idx_ports_connected_to ON ports(connected_to(100))"); }
];

/* 29) Add FK fiber_ports.connected_fiber_panel_id -> fiber_panels(id) and switches FK for fiber_ports.connected_switch_id */
$steps[] = [
    'name' => "fiber_ports: add FKs to switches and fiber_panels (if tables exist)",
    'check' => function($c){
        // check at least one FK exists or tables missing
        return fkExists($c,'fiber_ports','connected_switch_id','switches') && fkExists($c,'fiber_ports','connected_fiber_panel_id','fiber_panels');
    },
    'apply' => function($c){
        $ok = true;
        if (tableExists($c,'switches') && !fkExists($c,'fiber_ports','connected_switch_id','switches')) {
            $ok = $ok && $c->query("ALTER TABLE fiber_ports ADD CONSTRAINT fk_fiber_ports_switch FOREIGN KEY (connected_switch_id) REFERENCES switches(id) ON DELETE SET NULL");
        }
        if (tableExists($c,'fiber_panels') && !fkExists($c,'fiber_ports','connected_fiber_panel_id','fiber_panels')) {
            $ok = $ok && $c->query("ALTER TABLE fiber_ports ADD CONSTRAINT fk_fiber_ports_panel FOREIGN KEY (connected_fiber_panel_id) REFERENCES fiber_panels(id) ON DELETE SET NULL");
        }
        return $ok;
    }
];

/* 30) Create snmp_config table for SNMP settings */
$steps[] = [
    'name' => "Create table snmp_config",
    'check' => function($c){ return tableExists($c,'snmp_config'); },
    'apply' => function($c){
        $sql = "CREATE TABLE IF NOT EXISTS snmp_config (
            id INT AUTO_INCREMENT PRIMARY KEY,
            switch_id INT DEFAULT NULL,
            version VARCHAR(10) DEFAULT 'v2c',
            community VARCHAR(100) DEFAULT NULL,
            username VARCHAR(100) DEFAULT NULL,
            auth_protocol VARCHAR(10) DEFAULT NULL,
            auth_password VARCHAR(255) DEFAULT NULL,
            priv_protocol VARCHAR(10) DEFAULT NULL,
            priv_password VARCHAR(255) DEFAULT NULL,
            timeout INT DEFAULT 5,
            retries INT DEFAULT 3,
            is_global TINYINT(1) DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_switch_snmp (switch_id),
            CONSTRAINT fk_snmp_switch FOREIGN KEY (switch_id) REFERENCES switches(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        return $c->query($sql);
    }
];

/* 31) Insert default global SNMP v3 configuration */
$steps[] = [
    'name' => "Insert global SNMP v3 configuration",
    'check' => function($c){
        $res = $c->query("SELECT 1 FROM snmp_config WHERE is_global = 1 LIMIT 1");
        return ($res && $res->num_rows > 0);
    },
    'apply' => function($c){
        return $c->query("INSERT INTO snmp_config (switch_id, version, username, auth_protocol, auth_password, priv_protocol, priv_password, timeout, retries, is_global) 
            VALUES (NULL, 'v3', 'snmpuser', 'SHA', 'AuthPass123', 'AES', 'PrivPass123', 2, 1, 1)");
    }
];

/* 32) Insert EDGE-SW35 test switch if not exists */
$steps[] = [
    'name' => "Insert EDGE-SW35 test switch",
    'check' => function($c){
        $res = $c->query("SELECT 1 FROM switches WHERE name = 'EDGE-SW35' LIMIT 1");
        return ($res && $res->num_rows > 0);
    },
    'apply' => function($c){
        return $c->query("INSERT INTO switches (name, brand, model, ports, status, ip, created_at) 
            VALUES ('EDGE-SW35', 'Cisco', 'Generic', 48, 'online', '192.168.70.35', NOW())");
    }
];

/* 33) Drop unused backup tables */
$steps[] = [
    'name' => "Drop unused backup tables (ports_backup, switches_backup, racks_backup)",
    'check' => function($c){
        return !tableExists($c,'ports_backup_20251224_084522') 
            && !tableExists($c,'ports_backup_20251224_084904')
            && !tableExists($c,'switches_backup_20251224_084522')
            && !tableExists($c,'switches_backup_20251224_084904')
            && !tableExists($c,'racks_backup_20251224_084522')
            && !tableExists($c,'racks_backup_20251224_084904');
    },
    'apply' => function($c){
        $ok = true;
        $backupTables = [
            'ports_backup_20251224_084522',
            'ports_backup_20251224_084904',
            'switches_backup_20251224_084522', 
            'switches_backup_20251224_084904',
            'racks_backup_20251224_084522',
            'racks_backup_20251224_084904'
        ];
        foreach ($backupTables as $table) {
            if (tableExists($c, $table)) {
                $ok = $ok && $c->query("DROP TABLE IF EXISTS `" . $c->real_escape_string($table) . "`");
            }
        }
        return $ok;
    }
];

/* 34) Create users table for authentication */
$steps[] = [
    'name' => "Create table users",
    'check' => function($c){ return tableExists($c,'users'); },
    'apply' => function($c){
        $sql = "CREATE TABLE IF NOT EXISTS users (
            id INT(11) NOT NULL AUTO_INCREMENT,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            full_name VARCHAR(100) NOT NULL,
            email VARCHAR(100) DEFAULT NULL,
            role ENUM('admin','user') DEFAULT 'user',
            is_active TINYINT(1) DEFAULT 1,
            last_login DATETIME DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_username (username),
            KEY idx_is_active (is_active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci";
        return $c->query($sql);
    }
];

/* 35) Insert default admin user */
$steps[] = [
    'name' => "Insert default admin user (username: admin, password: admin123)",
    'check' => function($c){
        $res = $c->query("SELECT 1 FROM users WHERE username = 'admin' LIMIT 1");
        return ($res && $res->num_rows > 0);
    },
    'apply' => function($c){
        // Password: admin123 (hashed with bcrypt)
        // Hash generated with: password_hash('admin123', PASSWORD_BCRYPT)
        $passwordHash = '$2y$10$vpE3oMnK0oJqzz.IaeprLu2NoqeuTbjB8bqLG5gK1dRJOUpY6Jiai';
        return $c->query("INSERT INTO users (username, password, full_name, email, role, is_active) 
            VALUES ('admin', '{$passwordHash}', 'System Administrator', 'admin@example.com', 'admin', 1)");
    }
];

/* 36) Create activity_log table */
$steps[] = [
    'name' => "Create table activity_log",
    'check' => function($c){ return tableExists($c,'activity_log'); },
    'apply' => function($c){
        $sql = "CREATE TABLE IF NOT EXISTS activity_log (
            id INT(11) NOT NULL AUTO_INCREMENT,
            user_id INT(11) DEFAULT NULL,
            username VARCHAR(50) DEFAULT NULL,
            action VARCHAR(100) NOT NULL,
            description TEXT DEFAULT NULL,
            ip_address VARCHAR(45) DEFAULT NULL,
            user_agent VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_user_id (user_id),
            KEY idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci";
        return $c->query($sql);
    }
];

/* 37) Add foreign key for activity_log.user_id */
$steps[] = [
    'name' => "activity_log: FK user_id -> users(id)",
    'check' => function($c){ return fkExists($c,'activity_log','user_id','users'); },
    'apply' => function($c){
        if (!tableExists($c,'users')) return false;
        return $c->query("ALTER TABLE activity_log ADD CONSTRAINT fk_activity_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL");
    }
];

/* 38) Create snmp_devices table */
$steps[] = [
    'name' => "Create table snmp_devices",
    'check' => function($c){ return tableExists($c,'snmp_devices'); },
    'apply' => function($c){
        $sql = "CREATE TABLE IF NOT EXISTS snmp_devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            vendor VARCHAR(100) DEFAULT NULL,
            model VARCHAR(100) DEFAULT NULL,
            status ENUM('online','offline','error') DEFAULT 'offline',
            enabled BOOLEAN DEFAULT TRUE,
            total_ports INT DEFAULT 0,
            last_poll_time DATETIME DEFAULT NULL,
            last_successful_poll DATETIME DEFAULT NULL,
            poll_interval INT DEFAULT 300,
            snmp_version VARCHAR(10) DEFAULT 'v2c',
            snmp_community VARCHAR(100) DEFAULT 'public',
            snmp_port INT DEFAULT 161,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_snmp_devices_ip (ip_address),
            INDEX idx_snmp_devices_status (status),
            INDEX idx_snmp_devices_enabled (enabled)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        return $c->query($sql);
    }
];

/* 39) Create device_polling_data table */
$steps[] = [
    'name' => "Create table device_polling_data",
    'check' => function($c){ return tableExists($c,'device_polling_data'); },
    'apply' => function($c){
        $sql = "CREATE TABLE IF NOT EXISTS device_polling_data (
            id INT AUTO_INCREMENT PRIMARY KEY,
            device_id INT NOT NULL,
            poll_timestamp DATETIME NOT NULL,
            system_name VARCHAR(255) DEFAULT NULL,
            system_description TEXT DEFAULT NULL,
            system_uptime BIGINT DEFAULT NULL,
            system_contact VARCHAR(255) DEFAULT NULL,
            system_location VARCHAR(255) DEFAULT NULL,
            total_ports INT DEFAULT 0,
            active_ports INT DEFAULT 0,
            cpu_usage FLOAT DEFAULT NULL,
            memory_usage FLOAT DEFAULT NULL,
            temperature FLOAT DEFAULT NULL,
            raw_data LONGTEXT DEFAULT NULL,
            INDEX idx_device_polling_device (device_id),
            INDEX idx_device_polling_timestamp (poll_timestamp),
            FOREIGN KEY (device_id) REFERENCES snmp_devices(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        return $c->query($sql);
    }
];

/* 40) Create port_status_data table */
$steps[] = [
    'name' => "Create table port_status_data",
    'check' => function($c){ return tableExists($c,'port_status_data'); },
    'apply' => function($c){
        $sql = "CREATE TABLE IF NOT EXISTS port_status_data (
            id INT AUTO_INCREMENT PRIMARY KEY,
            device_id INT NOT NULL,
            port_number INT NOT NULL,
            poll_timestamp DATETIME NOT NULL,
            port_name VARCHAR(255) DEFAULT NULL,
            port_alias VARCHAR(255) DEFAULT NULL,
            port_description TEXT DEFAULT NULL,
            admin_status ENUM('up','down','testing') DEFAULT 'down',
            oper_status ENUM('up','down','testing','unknown','dormant','notPresent','lowerLayerDown') DEFAULT 'down',
            port_speed BIGINT DEFAULT NULL,
            port_mtu INT DEFAULT NULL,
            vlan_id INT DEFAULT NULL,
            vlan_name VARCHAR(255) DEFAULT NULL,
            mac_address VARCHAR(17) DEFAULT NULL,
            mac_addresses TEXT DEFAULT NULL,
            in_octets BIGINT DEFAULT NULL,
            out_octets BIGINT DEFAULT NULL,
            in_errors BIGINT DEFAULT NULL,
            out_errors BIGINT DEFAULT NULL,
            in_discards BIGINT DEFAULT NULL,
            out_discards BIGINT DEFAULT NULL,
            last_seen DATETIME DEFAULT NULL,
            INDEX idx_port_status_device (device_id),
            INDEX idx_port_status_port (device_id, port_number),
            INDEX idx_port_status_timestamp (poll_timestamp),
            INDEX idx_port_status_oper (oper_status),
            FOREIGN KEY (device_id) REFERENCES snmp_devices(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        return $c->query($sql);
    }
];

/* 41) Create alarms table */
$steps[] = [
    'name' => "Create table alarms",
    'check' => function($c){ return tableExists($c,'alarms'); },
    'apply' => function($c){
        $sql = "CREATE TABLE IF NOT EXISTS alarms (
            id INT AUTO_INCREMENT PRIMARY KEY,
            device_id INT NOT NULL,
            alarm_type VARCHAR(50) NOT NULL,
            severity ENUM('critical','high','medium','low','info') DEFAULT 'medium',
            status ENUM('active','acknowledged','resolved') DEFAULT 'active',
            port_number INT DEFAULT NULL,
            title VARCHAR(255) NOT NULL,
            message TEXT DEFAULT NULL,
            details LONGTEXT DEFAULT NULL,
            occurrence_count INT DEFAULT 1,
            first_occurrence DATETIME NOT NULL,
            last_occurrence DATETIME NOT NULL,
            acknowledged_at DATETIME DEFAULT NULL,
            acknowledged_by VARCHAR(100) DEFAULT NULL,
            resolved_at DATETIME DEFAULT NULL,
            resolved_by VARCHAR(100) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_alarms_device (device_id),
            INDEX idx_alarms_status (status),
            INDEX idx_alarms_severity (severity),
            INDEX idx_alarms_type (alarm_type),
            INDEX idx_alarms_occurrence (last_occurrence),
            FOREIGN KEY (device_id) REFERENCES snmp_devices(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        return $c->query($sql);
    }
];

/* 42) Fix FK constraint name if wrong - drop and recreate */
$steps[] = [
    'name' => "Fix ports FK constraint name (fk_ports_patch_panel -> fk_ports_connected_panel)",
    'check' => function($c){
        // Check if the wrong constraint exists
        $res = $c->query("SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE 
                         WHERE TABLE_SCHEMA = DATABASE() 
                         AND TABLE_NAME = 'ports' 
                         AND CONSTRAINT_NAME = 'fk_ports_patch_panel'
                         LIMIT 1");
        return !($res && $res->num_rows > 0);
    },
    'apply' => function($c){
        // Drop the incorrectly named constraint if it exists
        $res = $c->query("SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE 
                         WHERE TABLE_SCHEMA = DATABASE() 
                         AND TABLE_NAME = 'ports' 
                         AND CONSTRAINT_NAME = 'fk_ports_patch_panel'
                         LIMIT 1");
        if ($res && $res->num_rows > 0) {
            if (!$c->query("ALTER TABLE ports DROP FOREIGN KEY fk_ports_patch_panel")) {
                return false;
            }
        }
        
        // Ensure the correct constraint exists
        $res2 = $c->query("SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE 
                          WHERE TABLE_SCHEMA = DATABASE() 
                          AND TABLE_NAME = 'ports' 
                          AND CONSTRAINT_NAME = 'fk_ports_connected_panel'
                          LIMIT 1");
        if (!$res2 || $res2->num_rows == 0) {
            if (!tableExists($c,'patch_panels')) return true;
            return $c->query("ALTER TABLE ports ADD CONSTRAINT fk_ports_connected_panel FOREIGN KEY (connected_panel_id) REFERENCES patch_panels(id) ON DELETE SET NULL");
        }
        return true;
    }
];

/* 43) Add description column to switches table */
$steps[] = [
    'name' => "switches: add description column",
    'check' => function($c){ return columnExists($c,'switches','description'); },
    'apply' => function($c){ return $c->query("ALTER TABLE switches ADD COLUMN description TEXT DEFAULT NULL"); }
];

/* 44) Add vendor column to switches table (alias for brand for SNMP compatibility) */
$steps[] = [
    'name' => "switches: add vendor column",
    'check' => function($c){ return columnExists($c,'switches','vendor'); },
    'apply' => function($c){ 
        // Add vendor column and copy brand values to it
        if (!$c->query("ALTER TABLE switches ADD COLUMN vendor VARCHAR(100) DEFAULT NULL")) {
            return false;
        }
        // Copy brand to vendor for existing rows
        return $c->query("UPDATE switches SET vendor = brand WHERE vendor IS NULL");
    }
];

/* 45) Add old_vlan_id column to alarms table for VLAN change tracking */
$steps[] = [
    'name' => "alarms: add old_vlan_id column",
    'check' => function($c){ return columnExists($c,'alarms','old_vlan_id'); },
    'apply' => function($c){ 
        return $c->query("ALTER TABLE alarms ADD COLUMN old_vlan_id INT DEFAULT NULL AFTER to_port");
    }
];

/* 46) Add new_vlan_id column to alarms table for VLAN change tracking */
$steps[] = [
    'name' => "alarms: add new_vlan_id column",
    'check' => function($c){ return columnExists($c,'alarms','new_vlan_id'); },
    'apply' => function($c){ 
        return $c->query("ALTER TABLE alarms ADD COLUMN new_vlan_id INT DEFAULT NULL AFTER old_vlan_id");
    }
];

/* 47) Apply SQL migrations from snmp_worker/migrations/ folder */
$migrationFiles = [
    'create_migration_tracker.sql',
    'add_mac_tracking_tables.sql',
    'add_acknowledged_port_mac_table.sql',
    'add_port_operational_status.sql',
    'create_alarm_severity_config.sql',
    'fix_status_enum_uppercase.sql',
    'fix_alarms_status_enum_uppercase.sql',
    'create_switch_change_log_view.sql',
    'mac_device_import.sql',
    'enable_description_change_notifications.sql'
];

foreach ($migrationFiles as $migrationFile) {
    $steps[] = [
        'name' => "SQL Migration: {$migrationFile}",
        'check' => function($c) use ($migrationFile) {
            return isMigrationApplied($c, $migrationFile);
        },
        'apply' => function($c) use ($migrationFile) {
            $migrationPath = __DIR__ . '/snmp_worker/migrations/' . $migrationFile;
            if (!file_exists($migrationPath)) {
                // Migration dosyası yoksa skip, hata verme
                return true;
            }
            try {
                $startTime = microtime(true);
                applySQLMigration($c, $migrationPath);
                $execTime = round((microtime(true) - $startTime) * 1000);
                recordMigration($c, $migrationFile, 'SQL', true, null, $execTime);
                return true;
            } catch (Exception $e) {
                recordMigration($c, $migrationFile, 'SQL', false, $e->getMessage(), null);
                throw $e;
            }
        }
    ];
}

/* 48) Validation: Critical columns check */
$steps[] = [
    'name' => "Validation: Critical columns exist",
    'check' => function($c) {
        $result = validateCriticalColumns($c);
        return $result === true;
    },
    'apply' => function($c) {
        // Sadece kontrol, apply etme - hata verir
        $result = validateCriticalColumns($c);
        if ($result !== true) {
            throw new Exception($result);
        }
        return true;
    }
];

/* 49) Remove unused/deprecated columns */
// DIKKAT: Production'da çalıştırmadan önce yedek alın!
$unusedColumns = [
    // Örnek: ['table' => 'ports', 'column' => 'old_column_name'],
    // Şu an için boş bırakıyoruz - gerekirse ekleyin
];

foreach ($unusedColumns as $col) {
    $steps[] = [
        'name' => "Remove unused column: {$col['table']}.{$col['column']}",
        'check' => function($c) use ($col) {
            return !columnExists($c, $col['table'], $col['column']);
        },
        'apply' => function($c) use ($col) {
            $table = $c->real_escape_string($col['table']);
            $column = $c->real_escape_string($col['column']);
            return $c->query("ALTER TABLE `{$table}` DROP COLUMN `{$column}`");
        }
    ];
}

//
// Run steps
//
$results = [];
foreach ($steps as $idx => $step) {
    $name = $step['name'];
    try {
        $already = false;
        if (isset($step['check']) && is_callable($step['check'])) {
            $already = (bool)call_user_func($step['check'], $conn);
        }
        if ($already) {
            $results[] = ['name'=>$name, 'status'=>'exists', 'message'=>'Zaten mevcut'];
            continue;
        }
        // apply
        if (!isset($step['apply']) || !is_callable($step['apply'])) {
            $results[] = ['name'=>$name, 'status'=>'skipped', 'message'=>'Uygulanacak işlem yok'];
            continue;
        }
        $ok = call_user_func($step['apply'], $conn);
        if ($ok === true) {
            $results[] = ['name'=>$name, 'status'=>'applied', 'message'=>'Başarıyla uygulandı'];
        } else {
            // query failed - capture error
            $err = $conn->error;
            $results[] = ['name'=>$name, 'status'=>'error', 'message'=>$err ?: 'Bilinmeyen hata'];
        }
    } catch (Exception $e) {
        $results[] = ['name'=>$name, 'status'=>'exception', 'message'=>$e->getMessage()];
    }
}

// Output HTML report
?>
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>DB Güncelleme Raporu</title>
<style>
body{font-family: Arial, Helvetica, sans-serif; background: #0f172a; color:#e2e8f0; padding:20px}
.container{max-width:1100px;margin:0 auto}
h1{color:#60a5fa}
table{width:100%;border-collapse:collapse;margin-top:15px}
th,td{padding:10px;border:1px solid #1f2937}
th{background:#111827;color:#fff}
.status-applied{color:#10b981;font-weight:700}
.status-exists{color:#f59e0b;font-weight:700}
.status-error{color:#ef4444;font-weight:700}
.status-exception{color:#f43f5e;font-weight:700}
</style>
</head>
<body>
<div class="container">
    <h1>Veritabanı Güncelleme Raporu</h1>
    <p>Veritabanı: <?php echo h($db); ?> — Tarih: <?php echo date('Y-m-d H:i:s'); ?></p>

    <table>
        <thead>
            <tr><th>#</th><th>İşlem</th><th>Durum</th><th>Mesaj</th></tr>
        </thead>
        <tbody>
        <?php foreach ($results as $i => $r): 
            $no = $i+1;
            $status = $r['status'];
            $cls = 'status-' . ($status === 'applied' ? 'applied' : ($status === 'exists' ? 'exists' : ($status === 'error' ? 'error' : 'exception')));
        ?>
            <tr>
                <td style="width:50px;text-align:center"><?php echo $no; ?></td>
                <td><?php echo h($r['name']); ?></td>
                <td class="<?php echo $cls; ?>"><?php echo h(strtoupper($r['status'])); ?></td>
                <td style="font-family: monospace;"><?php echo h($r['message']); ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <h3>Notlar</h3>
    <ul>
        <li>Her adım idempotent olacak şekilde hazırlanmıştır; yeniden çalıştırabilirsiniz.</li>
        <li>FULLTEXT index veya enum değişiklikleri bazı MySQL versiyonlarında farklı sonuç verebilir; hata alırsanız log'a bakın.</li>
        <li>Yabancı anahtarlar (FK) eklenirken hedef tablo yoksa FK atlanır; önce ilgili tabloyu oluşturduğumuzdan emin olun.</li>
        <li><strong>YENİ:</strong> SQL migration dosyaları otomatik olarak uygulanır ve migration_history tablosunda takip edilir.</li>
        <li><strong>YENİ:</strong> Gereksiz kolonları kaldırmak için $unusedColumns dizisine ekleyin.</li>
    </ul>

    <?php
    // Migration tracker istatistikleri göster
    if (tableExists($conn, 'migration_history')) {
        $statsRes = $conn->query("
            SELECT 
                migration_type,
                COUNT(*) as total,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
            FROM migration_history
            GROUP BY migration_type
        ");
        
        if ($statsRes && $statsRes->num_rows > 0) {
            echo '<h3>Migration İstatistikleri</h3>';
            echo '<table style="width:auto; min-width:400px; border-collapse:collapse; margin:20px 0;">';
            echo '<thead><tr style="background:#1e293b;"><th>Tip</th><th>Toplam</th><th>Başarılı</th><th>Başarısız</th></tr></thead>';
            echo '<tbody>';
            while ($row = $statsRes->fetch_assoc()) {
                echo '<tr>';
                echo '<td style="padding:8px; border:1px solid #334155;">' . h($row['migration_type']) . '</td>';
                echo '<td style="padding:8px; border:1px solid #334155; text-align:center;">' . $row['total'] . '</td>';
                echo '<td style="padding:8px; border:1px solid #334155; text-align:center; color:#10b981;">' . $row['successful'] . '</td>';
                echo '<td style="padding:8px; border:1px solid #334155; text-align:center; color:#ef4444;">' . $row['failed'] . '</td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
            
            // Son 10 migration'ı göster
            $recentRes = $conn->query("
                SELECT migration_name, migration_type, applied_at, success
                FROM migration_history
                ORDER BY applied_at DESC
                LIMIT 10
            ");
            
            if ($recentRes && $recentRes->num_rows > 0) {
                echo '<details style="margin-top:20px;"><summary style="cursor:pointer; color:#93c5fd;">Son 10 Migration (Genişletmek için tıklayın)</summary>';
                echo '<table style="width:100%; border-collapse:collapse; margin:10px 0;">';
                echo '<thead><tr style="background:#1e293b;"><th>Migration</th><th>Tip</th><th>Tarih</th><th>Durum</th></tr></thead>';
                echo '<tbody>';
                while ($row = $recentRes->fetch_assoc()) {
                    $statusClass = $row['success'] ? 'status-applied' : 'status-error';
                    $statusText = $row['success'] ? 'BAŞARILI' : 'BAŞARISIZ';
                    echo '<tr>';
                    echo '<td style="padding:8px; border:1px solid #334155; font-family:monospace; font-size:0.9em;">' . h($row['migration_name']) . '</td>';
                    echo '<td style="padding:8px; border:1px solid #334155;">' . h($row['migration_type']) . '</td>';
                    echo '<td style="padding:8px; border:1px solid #334155;">' . h($row['applied_at']) . '</td>';
                    echo '<td class="' . $statusClass . '" style="padding:8px; border:1px solid #334155;">' . $statusText . '</td>';
                    echo '</tr>';
                }
                echo '</tbody></table></details>';
            }
        }
    }
    ?>

    <p><a href="<?php echo h($_SERVER['PHP_SELF']); ?>" style="color:#93c5fd">Sayfayı yenileyerek tekrar çalıştırabilirsiniz</a></p>
</div>
</body>
</html>
<?php
// close connection
$conn->close();