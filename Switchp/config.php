<?php
// config.php - centralized configuration
date_default_timezone_set('Europe/Athens');

class Config {
    private static $cfg = null;

    private static function init() {
        if (self::$cfg !== null) {
            return;
        }
        self::$cfg = [
            'env'          => getenv('APP_ENV')    ?: 'production',
            'db_host'      => getenv('DB_HOST')     ?: 'MANAGEENGINE\\SQLEXPRESS',
            'db_user'      => getenv('DB_USER')     ?: '',
            'db_pass'      => getenv('DB_PASS')     ?: '',
            'db_name'      => getenv('DB_NAME')     ?: 'switchdb',
            'log_file'     => __DIR__ . '/logs/app.log',
            'log_level'    => getenv('LOG_LEVEL')   ?: 'INFO',
            'retry_max'    => 3,
            'current_user' => 'system'
        ];
    }

    public static function get() {
        self::init();
        return self::$cfg;
    }

    public static function set(array $c) {
        self::init();
        self::$cfg = array_merge(self::$cfg, $c);
    }
}
