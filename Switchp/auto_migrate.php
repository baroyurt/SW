<?php
/**
 * Automatic Migration Runner
 * 
 * Bu script otomatik olarak bekleyen migration'ları tespit edip uygular
 * First-run detection ve otomatik deployment için kullanılır
 */

require_once __DIR__ . '/db.php';

class AutoMigrate {
    private $conn;
    private $migrationsDir;
    private $logFile;
    
    // Migration sırası - önemli!
    private $sqlMigrations = [
        'create_migration_tracker.sql',  // İlk olarak tracker'ı oluştur
        'create_alarm_severity_config.sql',
        'add_mac_tracking_tables.sql',
        'add_acknowledged_port_mac_table.sql',
        'create_switch_change_log_view.sql',
        'mac_device_import.sql',
        'fix_status_enum_uppercase.sql',
        'fix_alarms_status_enum_uppercase.sql',
        'enable_description_change_notifications.sql'
    ];
    
    private $pythonMigrations = [
        'create_tables.py',
        'add_snmp_v3_columns.py',
        'add_system_info_columns.py',
        'add_engine_id.py',
        'add_polling_data_columns.py',
        'add_port_config_columns.py',
        'add_alarm_notification_columns.py',
        'add_vlan_columns_to_alarms.py',
        'fix_status_enum_uppercase.py'
    ];
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->migrationsDir = __DIR__ . '/snmp_worker/migrations/';
        $this->logFile = __DIR__ . '/logs/auto_migrate_' . date('Y-m-d') . '.log';
        
        // Log dizinini oluştur
        if (!file_exists(__DIR__ . '/logs')) {
            mkdir(__DIR__ . '/logs', 0755, true);
        }
    }
    
    private function log($message, $level = 'INFO') {
        $timestamp = date('Y-m-d H:i:s');
        $logMessage = "[$timestamp] [$level] $message\n";
        file_put_contents($this->logFile, $logMessage, FILE_APPEND);
        
        // Konsola da yaz
        echo $logMessage;
    }
    
    /**
     * Migration tracker tablosunun var olup olmadığını kontrol et
     */
    private function migrationTrackerExists() {
        try {
            $result = $this->conn->query("SHOW TABLES LIKE 'migration_history'");
            return $result && $result->num_rows > 0;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Migration tracker'ı oluştur
     */
    private function createMigrationTracker() {
        $this->log('Migration tracker oluşturuluyor...');
        
        $trackerSql = $this->migrationsDir . 'create_migration_tracker.sql';
        if (!file_exists($trackerSql)) {
            $this->log('Migration tracker SQL dosyası bulunamadı: ' . $trackerSql, 'ERROR');
            return false;
        }
        
        return $this->executeSqlFile($trackerSql);
    }
    
    /**
     * Bir migration'ın uygulanıp uygulanmadığını kontrol et
     */
    private function isMigrationApplied($migrationName) {
        if (!$this->migrationTrackerExists()) {
            return false;
        }
        
        $stmt = $this->conn->prepare(
            "SELECT COUNT(*) as count FROM migration_history 
             WHERE migration_name = ? AND success = 1"
        );
        $stmt->bind_param('s', $migrationName);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        
        return $row['count'] > 0;
    }
    
    /**
     * Migration'ı kaydet
     */
    private function recordMigration($migrationName, $type, $success, $executionTime, $errorMessage = null) {
        if (!$this->migrationTrackerExists()) {
            return;
        }
        
        $stmt = $this->conn->prepare(
            "INSERT INTO migration_history 
             (migration_name, migration_type, success, execution_time_ms, error_message, applied_by) 
             VALUES (?, ?, ?, ?, ?, 'auto_migrate')
             ON DUPLICATE KEY UPDATE 
             success = VALUES(success),
             execution_time_ms = VALUES(execution_time_ms),
             error_message = VALUES(error_message),
             applied_at = CURRENT_TIMESTAMP"
        );
        $stmt->bind_param('ssiss', $migrationName, $type, $success, $executionTime, $errorMessage);
        $stmt->execute();
        $stmt->close();
    }
    
    /**
     * SQL dosyasını çalıştır
     */
    private function executeSqlFile($filePath) {
        $startTime = microtime(true);
        
        try {
            $sql = file_get_contents($filePath);
            if ($sql === false) {
                throw new Exception('Dosya okunamadı: ' . $filePath);
            }
            
            // SQL'i çalıştır (multi-query desteği)
            if ($this->conn->multi_query($sql)) {
                do {
                    // Sonuçları temizle
                    if ($result = $this->conn->store_result()) {
                        $result->free();
                    }
                } while ($this->conn->next_result());
            }
            
            // Hata kontrolü
            if ($this->conn->error) {
                throw new Exception($this->conn->error);
            }
            
            $executionTime = (microtime(true) - $startTime) * 1000;
            return ['success' => true, 'time' => $executionTime];
            
        } catch (Exception $e) {
            $executionTime = (microtime(true) - $startTime) * 1000;
            return ['success' => false, 'time' => $executionTime, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Python scriptini çalıştır
     */
    private function executePythonScript($filePath) {
        $startTime = microtime(true);
        
        try {
            $output = [];
            $returnVar = 0;
            
            // Python scriptini çalıştır
            exec("python \"$filePath\" 2>&1", $output, $returnVar);
            
            $executionTime = (microtime(true) - $startTime) * 1000;
            
            if ($returnVar !== 0) {
                throw new Exception('Python script başarısız: ' . implode("\n", $output));
            }
            
            return ['success' => true, 'time' => $executionTime];
            
        } catch (Exception $e) {
            $executionTime = (microtime(true) - $startTime) * 1000;
            return ['success' => false, 'time' => $executionTime, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Tüm pending migration'ları uygula
     */
    public function runPendingMigrations() {
        $this->log('========================================');
        $this->log('Otomatik Migration Başlatıldı');
        $this->log('========================================');
        
        $totalApplied = 0;
        $totalFailed = 0;
        
        // İlk olarak migration tracker'ı kontrol et ve oluştur
        if (!$this->migrationTrackerExists()) {
            $this->log('Migration tracker mevcut değil, oluşturuluyor...');
            if (!$this->createMigrationTracker()) {
                $this->log('Migration tracker oluşturulamadı!', 'ERROR');
                return ['success' => false, 'message' => 'Migration tracker oluşturulamadı'];
            }
            $this->log('Migration tracker başarıyla oluşturuldu');
        }
        
        // SQL Migration'ları uygula
        $this->log('SQL migration\'ları kontrol ediliyor...');
        foreach ($this->sqlMigrations as $migration) {
            if ($migration === 'create_migration_tracker.sql') {
                continue; // Zaten uygulandı
            }
            
            if ($this->isMigrationApplied($migration)) {
                $this->log("  ⏭️  Atlaniyor (zaten uygulanmış): $migration");
                continue;
            }
            
            $filePath = $this->migrationsDir . $migration;
            if (!file_exists($filePath)) {
                $this->log("  ⚠️  Dosya bulunamadı: $migration", 'WARNING');
                continue;
            }
            
            $this->log("  🔄 Uygulanıyor: $migration");
            $result = $this->executeSqlFile($filePath);
            
            if ($result['success']) {
                $this->log("  ✅ Başarılı: $migration (" . round($result['time']) . "ms)");
                $this->recordMigration($migration, 'SQL', 1, $result['time'], null);
                $totalApplied++;
            } else {
                $this->log("  ❌ Başarısız: $migration - " . $result['error'], 'ERROR');
                $this->recordMigration($migration, 'SQL', 0, $result['time'], $result['error']);
                $totalFailed++;
            }
        }
        
        // Python Migration'ları uygula
        $this->log('Python migration\'ları kontrol ediliyor...');
        
        // Python var mı kontrol et
        exec('python --version 2>&1', $output, $returnVar);
        if ($returnVar !== 0) {
            $this->log('  ⚠️  Python bulunamadı, Python migration\'lar atlanıyor', 'WARNING');
        } else {
            foreach ($this->pythonMigrations as $migration) {
                if ($this->isMigrationApplied($migration)) {
                    $this->log("  ⏭️  Atlaniyor (zaten uygulanmış): $migration");
                    continue;
                }
                
                $filePath = $this->migrationsDir . $migration;
                if (!file_exists($filePath)) {
                    $this->log("  ⚠️  Dosya bulunamadı: $migration", 'WARNING');
                    continue;
                }
                
                $this->log("  🔄 Çalıştırılıyor: $migration");
                $result = $this->executePythonScript($filePath);
                
                if ($result['success']) {
                    $this->log("  ✅ Başarılı: $migration (" . round($result['time']) . "ms)");
                    $this->recordMigration($migration, 'PYTHON', 1, $result['time'], null);
                    $totalApplied++;
                } else {
                    $this->log("  ❌ Başarısız: $migration - " . $result['error'], 'ERROR');
                    $this->recordMigration($migration, 'PYTHON', 0, $result['time'], $result['error']);
                    $totalFailed++;
                }
            }
        }
        
        $this->log('========================================');
        $this->log("Migration Tamamlandı: $totalApplied başarılı, $totalFailed başarısız");
        $this->log('========================================');
        
        return [
            'success' => true,
            'applied' => $totalApplied,
            'failed' => $totalFailed,
            'message' => "$totalApplied migration uygulandı, $totalFailed başarısız"
        ];
    }
    
    /**
     * Migration gerekli mi kontrol et
     */
    public function needsMigration() {
        if (!$this->migrationTrackerExists()) {
            return true; // Tracker yoksa kesinlikle migration gerekli
        }
        
        // SQL migration'ları kontrol et
        foreach ($this->sqlMigrations as $migration) {
            if ($migration === 'create_migration_tracker.sql') {
                continue;
            }
            if (!$this->isMigrationApplied($migration)) {
                return true;
            }
        }
        
        return false;
    }
}

// Script doğrudan çalıştırıldıysa, migration'ları uygula
if (php_sapi_name() === 'cli' || !isset($_SERVER['REQUEST_METHOD'])) {
    $migrate = new AutoMigrate($conn);
    $result = $migrate->runPendingMigrations();
    exit($result['success'] ? 0 : 1);
}
