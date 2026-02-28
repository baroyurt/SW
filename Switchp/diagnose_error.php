<?php
// Simple diagnostic script to find the error
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h1>Diagnostic Test</h1>";

// Test 1: PHP is working
echo "<p>✅ PHP is working</p>";

// Test 2: Check session
session_start();
echo "<p>✅ Session started</p>";

// Test 3: Check db.php
echo "<p>Testing database connection...</p>";
try {
    require_once 'db.php';
    echo "<p>✅ db.php loaded</p>";
    
    if (isset($conn)) {
        echo "<p>✅ Database connection variable exists</p>";
        
        // Test a simple query
        $result = $conn->query("SELECT 1");
        if ($result) {
            echo "<p>✅ Database query works</p>";
        } else {
            echo "<p>❌ Database query failed: " . $conn->error . "</p>";
        }
    } else {
        echo "<p>❌ Database connection variable not set</p>";
    }
} catch (Exception $e) {
    echo "<p>❌ Error loading db.php: " . $e->getMessage() . "</p>";
}

// Test 4: Check auth.php
echo "<p>Testing auth...</p>";
try {
    require_once 'auth.php';
    echo "<p>✅ auth.php loaded</p>";
} catch (Exception $e) {
    echo "<p>❌ Error loading auth.php: " . $e->getMessage() . "</p>";
}

// Test 5: Check config path
$configPath = __DIR__ . '/../../snmp_worker/config/config.yml';
echo "<p>Config path: $configPath</p>";
echo "<p>Config exists: " . (file_exists($configPath) ? "YES" : "NO") . "</p>";

// Test 6: Try to include snmp_admin.php components
echo "<p>Testing YAML parser...</p>";
try {
    function parseYamlConfig($path) {
        if (!file_exists($path)) {
            return null;
        }
        $content = file_get_contents($path);
        if ($content === false) {
            return null;
        }
        $lines = explode("\n", $content);
        $result = [];
        $currentKey = null;
        $currentArray = null;
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || $line[0] === '#') continue;
            
            if (strpos($line, ':') !== false) {
                list($key, $value) = array_map('trim', explode(':', $line, 2));
                if (empty($value) || $value === '[]') {
                    $result[$key] = [];
                    $currentKey = $key;
                    $currentArray = [];
                } else {
                    $result[$key] = $value;
                    $currentKey = null;
                }
            } elseif ($currentKey !== null && strpos($line, '- ') === 0) {
                $item = [];
                $itemLine = substr($line, 2);
                if (strpos($itemLine, ':') !== false) {
                    list($k, $v) = array_map('trim', explode(':', $itemLine, 2));
                    $item[$k] = $v;
                }
                if (!isset($result[$currentKey])) {
                    $result[$currentKey] = [];
                }
                if (!empty($item)) {
                    $result[$currentKey][] = $item;
                }
            }
        }
        return $result;
    }
    
    $config = parseYamlConfig($configPath);
    echo "<p>✅ YAML parser works</p>";
    echo "<p>Config loaded: " . ($config ? "YES (with defaults)" : "NO") . "</p>";
} catch (Exception $e) {
    echo "<p>❌ YAML parser error: " . $e->getMessage() . "</p>";
}

echo "<h2>Conclusion</h2>";
echo "<p>If all tests pass, then snmp_admin.php should work.</p>";
echo "<p>If you still get 500 error on snmp_admin.php, check Apache error logs.</p>";
echo "<p><strong>Note:</strong> Your URL should be: <code>http://localhost/test%202/Switchp/diagnose_error.php</code></p>";
echo "<p>Or with space: <code>http://localhost/test 2/Switchp/diagnose_error.php</code></p>";
?>
