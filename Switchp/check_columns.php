<?php
/**
 * check_columns.php
 * 
 * Diagnostic script to check which columns exist in switches table
 * This helps identify migration issues
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// DB credentials
$host = "127.0.0.1";
$user = "root";
$pass = "";
$db   = "switchdb";

try {
    $conn = new mysqli($host, $user, $pass, $db);
    if ($conn->connect_error) {
        throw new Exception("DB connection error: " . $conn->connect_error);
    }
    $conn->set_charset('utf8mb4');
} catch (Exception $e) {
    echo "<h1>Connection Error</h1><pre>" . htmlspecialchars($e->getMessage()) . "</pre>";
    exit;
}

echo "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Switches Table Column Check</title>";
echo "<style>body{font-family:sans-serif;margin:20px;}table{border-collapse:collapse;margin:20px 0;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}th{background-color:#4CAF50;color:white;}.exists{color:green;font-weight:bold;}.missing{color:red;font-weight:bold;}.sql{background:#f4f4f4;padding:10px;margin:10px 0;border-left:3px solid #4CAF50;}</style>";
echo "</head><body>";

echo "<h1>Switches Table Column Check</h1>";

// Check if switches table exists
$result = $conn->query("SHOW TABLES LIKE 'switches'");
if (!$result || $result->num_rows == 0) {
    echo "<p class='missing'>❌ Switches table does NOT exist!</p>";
    echo "</body></html>";
    exit;
}

echo "<p class='exists'>✅ Switches table exists</p>";

// Get all columns from switches table
$result = $conn->query("SHOW COLUMNS FROM switches");
if (!$result) {
    echo "<p class='missing'>Error getting columns: " . htmlspecialchars($conn->error) . "</p>";
    exit;
}

echo "<h2>Current Columns in 'switches' Table:</h2>";
echo "<table><tr><th>Column Name</th><th>Type</th><th>Null</th><th>Key</th><th>Default</th></tr>";

$columns = [];
while ($row = $result->fetch_assoc()) {
    $columns[] = $row['Field'];
    echo "<tr>";
    echo "<td>" . htmlspecialchars($row['Field']) . "</td>";
    echo "<td>" . htmlspecialchars($row['Type']) . "</td>";
    echo "<td>" . htmlspecialchars($row['Null']) . "</td>";
    echo "<td>" . htmlspecialchars($row['Key']) . "</td>";
    echo "<td>" . htmlspecialchars($row['Default'] ?? 'NULL') . "</td>";
    echo "</tr>";
}
echo "</table>";

// Check for expected columns
echo "<h2>Expected Columns Check:</h2>";
echo "<table><tr><th>Column</th><th>Status</th></tr>";

$expectedColumns = ['id', 'name', 'brand', 'vendor', 'model', 'ip', 'ports', 'status', 'rack_id', 'position_in_rack', 'description'];

foreach ($expectedColumns as $col) {
    $exists = in_array($col, $columns);
    echo "<tr>";
    echo "<td>" . htmlspecialchars($col) . "</td>";
    echo "<td class='" . ($exists ? 'exists' : 'missing') . "'>" . ($exists ? '✅ EXISTS' : '❌ MISSING') . "</td>";
    echo "</tr>";
}
echo "</table>";

// Check specifically for description and vendor
$hasDescription = in_array('description', $columns);
$hasVendor = in_array('vendor', $columns);

echo "<h2>Critical Columns Status:</h2>";
echo "<ul>";
echo "<li><strong>description:</strong> <span class='" . ($hasDescription ? 'exists' : 'missing') . "'>" . ($hasDescription ? '✅ EXISTS' : '❌ MISSING') . "</span></li>";
echo "<li><strong>vendor:</strong> <span class='" . ($hasVendor ? 'exists' : 'missing') . "'>" . ($hasVendor ? '✅ EXISTS' : '❌ MISSING') . "</span></li>";
echo "</ul>";

// If description is missing, provide SQL to add it
if (!$hasDescription) {
    echo "<h2>🔧 Fix for Missing 'description' Column:</h2>";
    echo "<p>The <strong>description</strong> column is missing. Run this SQL command manually:</p>";
    echo "<div class='sql'><code>ALTER TABLE switches ADD COLUMN description TEXT DEFAULT NULL;</code></div>";
    echo "<p>You can run this via phpMyAdmin, MySQL command line, or by creating a simple PHP script.</p>";
    
    echo "<h3>Quick Fix PHP Script:</h3>";
    echo "<div class='sql'><pre>&lt;?php
\$conn = new mysqli('127.0.0.1', 'root', '', 'switchdb');
if (\$conn->connect_error) die('Connection failed: ' . \$conn->connect_error);

\$sql = \"ALTER TABLE switches ADD COLUMN description TEXT DEFAULT NULL\";
if (\$conn->query(\$sql)) {
    echo \"✅ Description column added successfully!\";
} else {
    echo \"❌ Error: \" . \$conn->error;
}
\$conn->close();
?&gt;</pre></div>";
}

// If vendor is missing, provide SQL to add it
if (!$hasVendor) {
    echo "<h2>🔧 Fix for Missing 'vendor' Column:</h2>";
    echo "<p>The <strong>vendor</strong> column is missing. Run this SQL command manually:</p>";
    echo "<div class='sql'><code>ALTER TABLE switches ADD COLUMN vendor VARCHAR(100) DEFAULT NULL;</code></div>";
    echo "<div class='sql'><code>UPDATE switches SET vendor = brand WHERE vendor IS NULL;</code></div>";
}

echo "<hr>";
echo "<p><a href='update_database.php'>← Back to Database Update</a></p>";
echo "</body></html>";

$conn->close();
?>
