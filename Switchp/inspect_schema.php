<?php
// inspect_schema.php
// Çalıştır: php inspect_schema.php
$host = "127.0.0.1";
$user = "root";
$pass = "";
$db   = "switchdb";

$mysqli = new mysqli($host, $user, $pass, $db);
if ($mysqli->connect_error) {
    echo "CONNECT_ERROR: " . $mysqli->connect_error . PHP_EOL;
    exit(1);
}
$mysqli->set_charset('utf8mb4');

$res = $mysqli->query("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()");
$schema = [];
while ($row = $res->fetch_assoc()) {
    $table = $row['TABLE_NAME'];
    $colsRes = $mysqli->query("SELECT COLUMN_NAME, COLUMN_TYPE, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '" . $mysqli->real_escape_string($table) . "' ORDER BY ORDINAL_POSITION");
    $cols = [];
    while ($c = $colsRes->fetch_assoc()) {
        $cols[] = $c;
    }
    $schema[$table] = $cols;
}
echo json_encode($schema, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . PHP_EOL;
$mysqli->close();