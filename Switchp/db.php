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

// Ensure logs directory exists
if (!file_exists(__DIR__ . '/logs')) {
    mkdir(__DIR__ . '/logs', 0755, true);
}
?>