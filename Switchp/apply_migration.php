<?php
/**
 * Apply Migration Script
 * Applies the acknowledged_port_mac table migration
 */

require_once 'db.php';

echo "Applying migration: add_acknowledged_port_mac_table.sql\n";
echo "=======================================================\n\n";

// Read migration file
$migrationFile = __DIR__ . '/snmp_worker/migrations/add_acknowledged_port_mac_table.sql';
if (!file_exists($migrationFile)) {
    die("Error: Migration file not found: $migrationFile\n");
}

$sql = file_get_contents($migrationFile);

// Split SQL by semicolons and execute each statement
$statements = array_filter(array_map('trim', explode(';', $sql)));

$successCount = 0;
$errorCount = 0;

foreach ($statements as $statement) {
    if (empty($statement) || strpos(trim($statement), '--') === 0) {
        continue; // Skip empty or comment-only lines
    }
    
    echo "Executing: " . substr($statement, 0, 80) . "...\n";
    
    if ($conn->query($statement)) {
        echo "✓ Success\n\n";
        $successCount++;
    } else {
        // Check if error is "Duplicate" (column/key already exists) - treat as success
        if (strpos($conn->error, 'Duplicate') !== false || 
            strpos($conn->error, 'already exists') !== false) {
            echo "⚠ Already exists (skipped): " . $conn->error . "\n\n";
            $successCount++;
        } else {
            echo "✗ Error: " . $conn->error . "\n\n";
            $errorCount++;
        }
    }
}

echo "=======================================================\n";
echo "Migration complete!\n";
echo "Successful: $successCount\n";
echo "Errors: $errorCount\n";

$conn->close();
?>
