<?php
// core/Database.php
// Singleton PDO/sqlsrv wrapper with transaction, savepoint and retry support.

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db.php';  // loads MysqliPdoConn + helpers

class Database {
    private static ?Database $instance = null;
    private MysqliPdoConn $conn;
    private bool $inTransaction    = false;
    private int  $savepointCounter = 0;

    private function __construct() {
        $cfg    = Config::get();
        $server = $cfg['db_host'];
        $dbName = $cfg['db_name'];
        $user   = $cfg['db_user'];
        $pass   = $cfg['db_pass'];

        $dsn = "sqlsrv:Server={$server};Database={$dbName};TrustServerCertificate=1";
        try {
            $pdo = new PDO(
                $dsn,
                ($user === '') ? null : $user,
                ($pass === '') ? null : $pass,
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::SQLSRV_ATTR_ENCODING    => PDO::SQLSRV_ENCODING_UTF8,
                ]
            );
        } catch (PDOException $e) {
            throw new Exception("DB connect error: " . $e->getMessage());
        }
        $this->conn = new MysqliPdoConn($pdo);
    }

    public static function getInstance(): Database {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    public function getConnection(): MysqliPdoConn {
        return $this->conn;
    }

    public function beginTransaction(): void {
        if (!$this->inTransaction) {
            $this->conn->begin_transaction();
            $this->inTransaction    = true;
            $this->savepointCounter = 0;
            return;
        }
        $this->createSavepoint();
    }

    public function commit(): void {
        if ($this->savepointCounter > 0) {
            $this->savepointCounter--;
            return;
        }
        if ($this->inTransaction) {
            $this->conn->commit();
            $this->inTransaction = false;
        }
    }

    public function rollback(): void {
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
        $this->conn->query("SAVE TRANSACTION [{$name}]");
        return $name;
    }

    public function rollbackToSavepoint(?string $name = null): void {
        if ($name === null) {
            $name = 'SP_' . $this->savepointCounter . '_' . time();
        }
        $this->conn->query("ROLLBACK TRANSACTION [{$name}]");
    }

    public function withRetry(callable $fn, int $maxRetries = 3) {
        $attempt = 0;
        $delay   = 200;
        while (true) {
            try {
                return $fn();
            } catch (Exception $e) {
                $attempt++;
                $msg = $e->getMessage();
                $isDeadlock = stripos($msg, 'Deadlock')     !== false
                           || stripos($msg, '1205')         !== false
                           || stripos($msg, '40001')        !== false
                           || stripos($msg, 'Lock timeout') !== false
                           || stripos($msg, '1222')         !== false;
                if ($attempt <= $maxRetries && $isDeadlock) {
                    usleep($delay * 1000);
                    $delay *= 2;
                    continue;
                }
                throw $e;
            }
        }
    }
}
