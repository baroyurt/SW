<?php
// core/Database.php
// Singleton MySQLi wrapper with transaction, savepoint and retry support.

require_once __DIR__ . '/../config.php';

class Database {
    private static $instance = null;
    /** @var mysqli */
    private $conn;
    private $inTransaction = false;
    private $savepointCounter = 0;

    private function __construct() {
        $cfg = Config::get();
        $this->conn = new mysqli($cfg['db_host'], $cfg['db_user'], $cfg['db_pass'], $cfg['db_name']);
        if ($this->conn->connect_error) {
            throw new Exception("DB connect error: " . $this->conn->connect_error);
        }
        $this->conn->set_charset('utf8mb4');

        // Set reasonable timeouts
        $this->conn->query("SET SESSION innodb_lock_wait_timeout = 50");
    }

    public static function getInstance(): Database {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    public function getConnection(): mysqli {
        return $this->conn;
    }

    public function beginTransaction() {
        if (!$this->inTransaction) {
            $this->conn->begin_transaction(MYSQLI_TRANS_START_READ_WRITE);
            $this->inTransaction = true;
            $this->savepointCounter = 0;
            return;
        }
        // nested transaction -> savepoint
        $this->createSavepoint();
    }

    public function commit() {
        if ($this->savepointCounter > 0) {
            // release savepoint (no direct mysqli release needed)
            $this->savepointCounter--;
            return;
        }
        if ($this->inTransaction) {
            $this->conn->commit();
            $this->inTransaction = false;
        }
    }

    public function rollback() {
        if ($this->savepointCounter > 0) {
            $this->rollbackToSavepoint();
            $this->savepointCounter--;
            return;
        }
        if ($this->inTransaction) {
            $this->conn->rollback();
            $this->inTransaction = false;
        }
    }

    public function createSavepoint(): string {
        $this->savepointCounter++;
        $name = 'SP_' . $this->savepointCounter . '_' . time();
        $this->conn->query("SAVEPOINT {$name}");
        return $name;
    }

    public function rollbackToSavepoint(string $name = null) {
        if ($name === null) {
            $name = 'SP_' . $this->savepointCounter . '_' . time();
        }
        $this->conn->query("ROLLBACK TO SAVEPOINT {$name}");
    }

    /**
     * Execute callable with automatic retry for deadlocks and lock timeouts.
     * @param callable $fn () => mixed
     * @param int $maxRetries
     * @return mixed
     * @throws Exception
     */
    public function withRetry(callable $fn, int $maxRetries = 3) {
        $attempt = 0;
        $delay = 200; // ms
        while (true) {
            try {
                return $fn();
            } catch (Exception $e) {
                $attempt++;
                $code = $this->conn->errno;
                $msg = $e->getMessage();
                // MySQL deadlock: 1213, lock wait timeout: 1205
                if ($attempt <= $maxRetries && (strpos($msg, 'Deadlock') !== false || $code === 1213 || $code === 1205 || stripos($msg, 'Lock wait timeout') !== false)) {
                    usleep($delay * 1000);
                    $delay *= 2;
                    continue;
                }
                throw $e;
            }
        }
    }
}