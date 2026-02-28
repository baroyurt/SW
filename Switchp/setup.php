<?php
/**
 * Setup Script
 * Initializes the database and applies migrations
 */

require_once 'config.php';

// Get configuration
$cfg = Config::get();

echo "================================\n";
echo "Switch Management System Setup\n";
echo "================================\n\n";

// Connect to database
echo "Connecting to database...\n";
$conn = new mysqli($cfg['db_host'], $cfg['db_user'], $cfg['db_pass'], $cfg['db_name']);

if ($conn->connect_error) {
    die("ERROR: Connection failed: " . $conn->connect_error . "\n");
}

echo "✓ Connected successfully\n\n";

$conn->set_charset("utf8mb4");

// Function to run SQL file
function runSQLFile($conn, $filepath) {
    if (!file_exists($filepath)) {
        echo "WARNING: File not found: $filepath\n";
        return false;
    }
    
    $sql = file_get_contents($filepath);
    
    // Split by semicolons (simple approach)
    $statements = array_filter(array_map('trim', explode(';', $sql)));
    
    $success = 0;
    $errors = 0;
    
    foreach ($statements as $statement) {
        if (empty($statement) || strpos($statement, '--') === 0) {
            continue;
        }
        
        if ($conn->query($statement)) {
            $success++;
        } else {
            // Ignore duplicate entry errors
            if (strpos($conn->error, 'Duplicate entry') === false && 
                strpos($conn->error, 'already exists') === false) {
                echo "  Warning: " . $conn->error . "\n";
                $errors++;
            }
        }
    }
    
    echo "  ✓ Executed $success statements";
    if ($errors > 0) {
        echo " ($errors warnings)";
    }
    echo "\n";
    
    return true;
}

// Apply migrations
echo "Applying migrations...\n";

$migrationsDir = __DIR__ . '/migrations';
if (is_dir($migrationsDir)) {
    $migrations = glob($migrationsDir . '/*.sql');
    sort($migrations);
    
    foreach ($migrations as $migration) {
        $filename = basename($migration);
        echo "  Running: $filename\n";
        runSQLFile($conn, $migration);
    }
} else {
    echo "  No migrations directory found\n";
}

echo "\n";

// Check if users table exists and has data
echo "Checking users...\n";
$result = $conn->query("SELECT COUNT(*) as count FROM users");
if ($result) {
    $row = $result->fetch_assoc();
    if ($row['count'] > 0) {
        echo "  ✓ Found " . $row['count'] . " user(s)\n";
    } else {
        echo "  ⚠ No users found. Creating default admin user...\n";
        $password = password_hash('admin123', PASSWORD_DEFAULT);
        $conn->query("INSERT INTO users (username, password, full_name, email, role) 
                     VALUES ('admin', '$password', 'Administrator', 'admin@example.com', 'admin')");
        echo "  ✓ Default admin user created (username: admin, password: admin123)\n";
    }
} else {
    echo "  ⚠ Users table not found\n";
}

echo "\n";

// Check SNMP worker tables
echo "Checking SNMP worker integration...\n";
$snmpTables = ['snmp_devices', 'device_polling_data', 'port_status_data', 'alarms'];
$foundTables = 0;

foreach ($snmpTables as $table) {
    $result = $conn->query("SHOW TABLES LIKE '$table'");
    if ($result && $result->num_rows > 0) {
        $foundTables++;
    }
}

if ($foundTables === count($snmpTables)) {
    echo "  ✓ All SNMP worker tables found\n";
    
    // Check for data
    $result = $conn->query("SELECT COUNT(*) as count FROM snmp_devices");
    if ($result) {
        $row = $result->fetch_assoc();
        echo "  ✓ Found " . $row['count'] . " SNMP device(s)\n";
    }
} else {
    echo "  ⚠ SNMP worker tables not found ($foundTables/" . count($snmpTables) . ")\n";
    echo "  Run SNMP worker migration: python3 snmp_worker/migrations/create_tables.py\n";
}

echo "\n";

// Summary
echo "================================\n";
echo "Setup Complete!\n";
echo "================================\n\n";

echo "Next steps:\n";
echo "1. Access the system: http://localhost/Switchp/\n";
echo "2. Login with: admin / admin123\n";
echo "3. Change the default password\n";
echo "4. Configure and start SNMP worker if needed\n\n";

$conn->close();
