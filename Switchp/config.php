<?php
// config.php - centralized configuration
class Config {
    private static $cfg = [
        'env' => 'development', // change to 'production' on prod
        'db_host' => '127.0.0.1',
        'db_user' => 'root',
        'db_pass' => '',
        'db_name' => 'switchdb',
        'log_file' => __DIR__ . '/logs/app.log',
        'log_level' => 'INFO',
        'retry_max' => 3,
        'current_user' => 'system'
    ];

    public static function get() {
        return self::$cfg;
    }

    public static function set(array $c) {
        self::$cfg = array_merge(self::$cfg, $c);
    }
}