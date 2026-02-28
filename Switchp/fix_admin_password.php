#!/usr/bin/env php
<?php
/**
 * Fix Admin Password
 * 
 * This script updates the admin user password hash to the correct value.
 * Run this if you're having trouble logging in with admin/admin123
 */

// Database credentials
$host = "127.0.0.1";
$user = "root";
$pass = "";
$db   = "switchdb";

echo "=== Admin Password Fix Script ===\n\n";

// Connect to database
try {
    $conn = new mysqli($host, $user, $pass, $db);
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    $conn->set_charset('utf8mb4');
    echo "✓ Connected to database\n";
} catch (Exception $e) {
    echo "✗ Error: " . $e->getMessage() . "\n";
    echo "\nPlease ensure:\n";
    echo "1. MySQL is running\n";
    echo "2. Database 'switchdb' exists\n";
    echo "3. Database credentials are correct\n";
    exit(1);
}

// Check if users table exists
$result = $conn->query("SHOW TABLES LIKE 'users'");
if ($result->num_rows == 0) {
    echo "✗ Error: 'users' table does not exist\n";
    echo "\nPlease run update_database.php first:\n";
    echo "  php update_database.php\n";
    exit(1);
}
echo "✓ Users table exists\n";

// Check if admin user exists
$result = $conn->query("SELECT id, username FROM users WHERE username = 'admin'");
if ($result->num_rows == 0) {
    echo "! Admin user does not exist, creating...\n";
    
    // Create admin user with correct password
    $passwordHash = '$2y$10$vpE3oMnK0oJqzz.IaeprLu2NoqeuTbjB8bqLG5gK1dRJOUpY6Jiai';
    $stmt = $conn->prepare("INSERT INTO users (username, password, full_name, email, role, is_active) VALUES (?, ?, ?, ?, ?, ?)");
    $username = 'admin';
    $fullName = 'System Administrator';
    $email = 'admin@example.com';
    $role = 'admin';
    $active = 1;
    $stmt->bind_param('sssssi', $username, $passwordHash, $fullName, $email, $role, $active);
    
    if ($stmt->execute()) {
        echo "✓ Admin user created successfully\n";
    } else {
        echo "✗ Error creating admin user: " . $stmt->error . "\n";
        exit(1);
    }
} else {
    echo "✓ Admin user exists\n";
    
    // Update password to correct hash
    echo "! Updating password to correct hash...\n";
    $passwordHash = '$2y$10$vpE3oMnK0oJqzz.IaeprLu2NoqeuTbjB8bqLG5gK1dRJOUpY6Jiai';
    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = 'admin'");
    $stmt->bind_param('s', $passwordHash);
    
    if ($stmt->execute()) {
        echo "✓ Password updated successfully\n";
    } else {
        echo "✗ Error updating password: " . $stmt->error . "\n";
        exit(1);
    }
}

// Verify the password works
echo "\n=== Verification ===\n";
$result = $conn->query("SELECT password FROM users WHERE username = 'admin'");
$row = $result->fetch_assoc();
$storedHash = $row['password'];

if (password_verify('admin123', $storedHash)) {
    echo "✓ Password verification successful\n";
    echo "\n=== SUCCESS ===\n";
    echo "You can now login with:\n";
    echo "  Username: admin\n";
    echo "  Password: admin123\n";
} else {
    echo "✗ Password verification failed\n";
    echo "Stored hash: $storedHash\n";
    exit(1);
}

$conn->close();
