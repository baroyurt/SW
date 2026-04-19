<?php
/**
 * Database Connection — SQL Server (sqlsrv) via PDO
 * Provides a mysqli-compatible wrapper so existing code remains unchanged.
 */

require_once 'config.php';

error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

ob_start();

if (!file_exists(__DIR__ . '/logs')) {
    mkdir(__DIR__ . '/logs', 0755, true);
}

// Define mysqli constants so legacy fetch_all(MYSQLI_ASSOC) calls work
if (!defined('MYSQLI_ASSOC')) define('MYSQLI_ASSOC', 1);
if (!defined('MYSQLI_NUM'))   define('MYSQLI_NUM',   2);
if (!defined('MYSQLI_BOTH'))  define('MYSQLI_BOTH',  3);

// ─────────────────────────────────────────────────────────────────────────────
// Result wrapper — exposes fetch_assoc(), fetch_all(), num_rows
// ─────────────────────────────────────────────────────────────────────────────
class MysqliPdoResult {
    private $rows   = [];
    private $cursor = 0;
    public  $num_rows = 0;

    public function __construct(PDOStatement $stmt) {
        try {
            $this->rows     = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $this->num_rows = count($this->rows);
        } catch (Throwable $e) {
            $this->rows     = [];
            $this->num_rows = 0;
        }
    }

    public function fetch_assoc() {
        return ($this->cursor < $this->num_rows)
            ? $this->rows[$this->cursor++]
            : null;
    }

    public function fetch_all($mode = null): array {
        return $this->rows;
    }

    /** Returns the current row as a numerically-indexed array (mysqli fetch_row equivalent). */
    public function fetch_row(): ?array {
        $row = $this->fetch_assoc();
        return $row !== null ? array_values($row) : null;
    }

    public function free(): void { $this->rows = []; }
    public function close(): void { $this->free(); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Statement wrapper — exposes bind_param(), execute(), get_result(), close()
// ─────────────────────────────────────────────────────────────────────────────
class MysqliPdoStmt {
    private PDO    $pdo;
    private string $sql;
    private array  $params     = [];
    private ?PDOStatement $pdoStmt = null;
    private MysqliPdoConn $connRef;
    public  int    $affected_rows = 0;
    public  string $error = '';

    public function __construct(PDO $pdo, string $sql, MysqliPdoConn $connRef) {
        $this->pdo     = $pdo;
        $this->sql     = MysqliPdoConn::transformSql($sql);
        $this->connRef = $connRef;
    }

    public function bind_param(string $types, ...$vars): void {
        $this->params = $vars;
    }

    public function execute(?array $vars = null): bool {
        $params = $vars ?? $this->params;
        try {
            $this->pdoStmt = $this->pdo->prepare($this->sql);
            $ok = $this->pdoStmt->execute($params);
            $this->affected_rows = $this->pdoStmt->rowCount();
            $this->connRef->setLastRowCount($this->affected_rows);
            try {
                $lid = $this->pdo->lastInsertId();
                if ($lid) $this->connRef->setLastInsertId((int)$lid);
            } catch (Throwable $e) {}
            return $ok;
        } catch (Throwable $e) {
            $this->error = $e->getMessage();
            $this->connRef->setError($e->getMessage(), (int)$e->getCode());
            // Suppress deadlock errors here: they will be retried by executeWithDeadlockRetry
            // and logged only if all retries are exhausted.
            $isDeadlock = strpos($e->getMessage(), '40001') !== false
                || strpos($e->getMessage(), '1205')  !== false
                || strpos($e->getMessage(), '1213')  !== false
                || stripos($e->getMessage(), 'deadlock') !== false;
            if (!$isDeadlock) {
                error_log("MysqliPdoStmt::execute error: " . $e->getMessage() . " | SQL: " . $this->sql);
            }
            return false;
        }
    }

    public function get_result(): ?MysqliPdoResult {
        return $this->pdoStmt ? new MysqliPdoResult($this->pdoStmt) : null;
    }

    public function store_result(): void {}

    public function close(): void {
        $this->pdoStmt = null;
        $this->params  = [];
    }

    public function __get(string $name) {
        if ($name === 'num_rows') {
            $r = $this->get_result();
            return $r ? $r->num_rows : 0;
        }
        return null;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection wrapper — exposes full mysqli-like interface
// ─────────────────────────────────────────────────────────────────────────────
class MysqliPdoConn {
    private PDO    $pdo;
    private string $lastError      = '';
    private int    $lastErrno      = 0;
    private int    $lastInsertId   = 0;
    private int    $lastRowCount   = 0;
    public  bool   $in_transaction = false;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    public function setError(string $msg, int $code = 0): void {
        $this->lastError  = $msg;
        $this->lastErrno  = $code;
    }

    public function setLastRowCount(int $n): void { $this->lastRowCount = $n; }
    public function setLastInsertId(int $n): void { $this->lastInsertId = $n; }

    /**
     * Translate MySQL-specific SQL to T-SQL.
     */
    public static function transformSql(string $sql): string {
        // CREATE TABLE IF NOT EXISTS with MySQL DDL → SQL Server equivalent.
        // Must run first so subsequent rewrites (TIMESTAMP, BOOLEAN, etc.) are
        // applied to the already-normalised DDL body.
        if (stripos($sql, 'CREATE TABLE IF NOT EXISTS') !== false) {
            $sql = self::_convertMysqlCreateTable($sql);
        }

        // Strip MySQL COLLATE clauses (e.g. COLLATE utf8mb4_general_ci).
        // SQL Server uses its own collation names; MySQL collations are invalid.
        $sql = preg_replace('/\s+COLLATE\s+utf8[a-zA-Z0-9_]*/i', '', $sql);

        // NOW() → GETDATE()
        $sql = preg_replace('/\bNOW\s*\(\s*\)/i', 'GETDATE()', $sql);

        // CURDATE() → CAST(GETDATE() AS DATE)
        $sql = preg_replace('/\bCURDATE\s*\(\s*\)/i', 'CAST(GETDATE() AS DATE)', $sql);

        // DATE(expr) → CAST(expr AS DATE)   e.g. DATE(change_timestamp) → CAST(change_timestamp AS DATE)
        $sql = preg_replace_callback(
            '/\bDATE\s*\(\s*([^()]+?)\s*\)/i',
            fn($m) => 'CAST(' . $m[1] . ' AS DATE)',
            $sql
        );

        // DATABASE() → DB_NAME()
        $sql = preg_replace('/\bDATABASE\s*\(\s*\)/i', 'DB_NAME()', $sql);

        // GETDATE() - INTERVAL n UNIT (arithmetic style, after NOW→GETDATE) → DATEADD(unit, -n, GETDATE())
        $sql = preg_replace_callback(
            '/GETDATE\s*\(\s*\)\s*-\s*INTERVAL\s+(\d+)\s+(\w+)/i',
            fn($m) => "DATEADD({$m[2]}, -{$m[1]}, GETDATE())",
            $sql
        );

        // FIELD(expr, 'v1', 'v2', ...) → CASE expr WHEN 'v1' THEN 1 WHEN 'v2' THEN 2 ... ELSE n+1 END
        // Uses a manual balanced-parentheses scan to handle nested function calls inside FIELD().
        // Performance is O(n) per FIELD() call; typical SQL strings are short, so this is fine.
        $sql = self::_transformFieldCalls($sql);

        // SHOW COLUMNS FROM `table` LIKE 'col' → INFORMATION_SCHEMA query
        $sql = preg_replace_callback(
            '/SHOW\s+COLUMNS\s+FROM\s+`?(\w+)`?\s+LIKE\s+\'([^\']*)\'/i',
            fn($m) => "SELECT COLUMN_NAME AS [Field] FROM INFORMATION_SCHEMA.COLUMNS"
                    . " WHERE TABLE_NAME = '{$m[1]}' AND COLUMN_NAME LIKE '{$m[2]}'",
            $sql
        );

        // SHOW COLUMNS FROM `table` WHERE Type LIKE ... → INFORMATION_SCHEMA query
        $sql = preg_replace_callback(
            '/SHOW\s+COLUMNS\s+FROM\s+`?(\w+)`?\s+WHERE\s+(.+)/i',
            function ($m) {
                $table = $m[1];
                // Map MySQL "Type" column alias to SQL Server DATA_TYPE
                $where = preg_replace('/\bType\b/i', 'DATA_TYPE', $m[2]);
                $where = preg_replace('/\bCOLUMN_TYPE\b/i', 'DATA_TYPE', $where);
                return "SELECT COLUMN_NAME AS [Field], DATA_TYPE AS [Type]"
                     . " FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{$table}' AND ({$where})";
            },
            $sql
        );

        // SHOW TABLES LIKE 'pattern' → INFORMATION_SCHEMA query
        $sql = preg_replace_callback(
            '/SHOW\s+TABLES\s+LIKE\s+\'([^\']*)\'/i',
            fn($m) => "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES"
                    . " WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_NAME LIKE '{$m[1]}'",
            $sql
        );

        // SHOW TABLES (no LIKE) → INFORMATION_SCHEMA query
        $sql = preg_replace(
            '/\bSHOW\s+TABLES\b/i',
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'",
            $sql
        );

        // DATE_ADD(GETDATE(), INTERVAL n UNIT) → DATEADD(unit, n, GETDATE())
        $sql = preg_replace_callback(
            '/DATE_ADD\s*\(\s*GETDATE\s*\(\s*\)\s*,\s*INTERVAL\s+(\d+)\s+(\w+)\s*\)/i',
            fn($m) => "DATEADD({$m[2]}, {$m[1]}, GETDATE())",
            $sql
        );

        // DATE_ADD(GETDATE(), INTERVAL ? UNIT) → DATEADD(unit, ?, GETDATE())
        $sql = preg_replace_callback(
            '/DATE_ADD\s*\(\s*GETDATE\s*\(\s*\)\s*,\s*INTERVAL\s+\?\s+(\w+)\s*\)/i',
            fn($m) => "DATEADD({$m[1]}, ?, GETDATE())",
            $sql
        );

        // DATE_SUB(GETDATE(), INTERVAL n UNIT) → DATEADD(unit, -n, GETDATE())
        $sql = preg_replace_callback(
            '/DATE_SUB\s*\(\s*GETDATE\s*\(\s*\)\s*,\s*INTERVAL\s+(\d+)\s+(\w+)\s*\)/i',
            fn($m) => "DATEADD({$m[2]}, -{$m[1]}, GETDATE())",
            $sql
        );

        // DATE_SUB(GETDATE(), INTERVAL ? UNIT) → DATEADD(unit, (-1 * ?), GETDATE())
        $sql = preg_replace_callback(
            '/DATE_SUB\s*\(\s*GETDATE\s*\(\s*\)\s*,\s*INTERVAL\s+\?\s+(\w+)\s*\)/i',
            fn($m) => "DATEADD({$m[1]}, (-1 * ?), GETDATE())",
            $sql
        );

        // Remove FOR UPDATE
        $sql = preg_replace('/\s+FOR\s+UPDATE\b/i', '', $sql);

        // MySQL multi-table UPDATE with JOINs is not valid T-SQL.
        // MySQL:  UPDATE t1 a1  [LEFT|RIGHT|INNER] JOIN t2 a2 ON …  SET a1.col=?  WHERE …
        // T-SQL:  UPDATE a1 SET a1.col=?  FROM t1 a1  JOIN t2 a2 ON …  WHERE …
        //
        // The regex captures:
        //   group 1 – table name (e.g. ports)
        //   group 2 – alias      (e.g. p)
        //   group 3 – all JOIN clauses
        //   group 4 – SET assignments
        //   group 5 – WHERE condition (optional, to end of string)
        $sql = preg_replace_callback(
            '/\bUPDATE\s+(\w+)\s+(\w+)\s+((?:(?:LEFT|RIGHT|INNER|OUTER|CROSS)?\s*JOIN\s+\S+\s+\w+\s+ON\s+.+?)+?)\s*\bSET\b\s*(.+?)(?:\s*\bWHERE\b\s*(.+))?$/is',
            function ($m) {
                $table = trim($m[1]);
                $alias = trim($m[2]);
                $joins = trim($m[3]);
                $sets  = trim($m[4]);
                $where = isset($m[5]) ? trim($m[5]) : '';
                $result = "UPDATE {$alias} SET {$sets} FROM {$table} {$alias} {$joins}";
                if ($where !== '') {
                    $result .= " WHERE {$where}";
                }
                return $result;
            },
            $sql
        );

        // MySQL backtick quoting → SQL Server bracket quoting (before LIMIT handling)
        $sql = preg_replace('/`([^`]+)`/', '[$1]', $sql);

        // LIMIT n OFFSET m → OFFSET m ROWS FETCH NEXT n ROWS ONLY  (literal numbers)
        $sql = preg_replace(
            '/\bLIMIT\s+(\d+)\s+OFFSET\s+(\d+)\b/i',
            'OFFSET $2 ROWS FETCH NEXT $1 ROWS ONLY',
            $sql
        );

        // LIMIT ? OFFSET ? → OFFSET ? ROWS FETCH NEXT ? ROWS ONLY  (bound parameters)
        // NOTE: callers that use this pattern must bind (offset, limit) — reversed order.
        $sql = preg_replace(
            '/\bLIMIT\s+\?\s+OFFSET\s+\?\s*/i',
            'OFFSET ? ROWS FETCH NEXT ? ROWS ONLY ',
            $sql
        );

        // DELETE ... LIMIT n → DELETE TOP (n) ...
        $sql = preg_replace_callback(
            '/\b(DELETE\s+(?:FROM\s+)?)\s*(\[?\w+\]?)\s*(.*?)\s+LIMIT\s+(\d+)/is',
            fn($m) => "DELETE TOP ({$m[4]}) FROM {$m[2]} {$m[3]}",
            $sql
        );

        // LIMIT n or LIMIT ? (anywhere, including subqueries) → move n / (?) to TOP on
        // the corresponding SELECT.  Process rightmost occurrence first so earlier
        // positions are not disturbed.
        while (preg_match_all('/\bLIMIT\s+(\d+|\?)\s*/i', $sql, $allM, PREG_OFFSET_CAPTURE)) {
            $lastIdx    = count($allM[0]) - 1;
            $limitStart = $allM[0][$lastIdx][1];
            $limitLen   = strlen($allM[0][$lastIdx][0]);
            $n          = $allM[1][$lastIdx][0]; // may be a digit string or '?'

            $before    = substr($sql, 0, $limitStart);
            $selectPos = strrpos(strtoupper($before), 'SELECT');
            if ($selectPos === false) {
                break;
            }

            // Remove LIMIT n / LIMIT ?
            $sql = substr($sql, 0, $limitStart) . substr($sql, $limitStart + $limitLen);
            // Insert TOP n / TOP (?) immediately after SELECT keyword
            $topStr = ctype_digit((string)$n) ? " TOP $n" : " TOP (?)";
            $sql = substr($sql, 0, $selectPos + 6) . $topStr . substr($sql, $selectPos + 6);
        }

        return $sql;
    }

    /**
     * Convert a MySQL-dialect CREATE TABLE IF NOT EXISTS statement to T-SQL.
     *
     * Handles the MySQL-specific syntax that appears in the defensive "ensure
     * table exists" guards scattered across getData.php and maintenance_api.php:
     *   - AUTO_INCREMENT        → IDENTITY(1,1)
     *   - BOOLEAN / TINYINT(1)  → BIT
     *   - TEXT                  → NVARCHAR(MAX)
     *   - TIMESTAMP             → DATETIME
     *   - CURRENT_TIMESTAMP     → GETDATE()
     *   - DEFAULT TRUE/FALSE    → DEFAULT 1/0
     *   - ON UPDATE …           → (removed)
     *   - ENUM(…)               → NVARCHAR(50)
     *   - INDEX name (cols)     → (removed; SQL Server requires separate statement)
     *   - UNIQUE KEY name(cols) → CONSTRAINT name UNIQUE (cols)
     *   - ENGINE=… / CHARSET=… / COLLATE=… table options → (removed)
     *
     * Wraps the result with:
     *   IF OBJECT_ID(N'tbl', 'U') IS NULL CREATE TABLE tbl (…)
     */
    private static function _convertMysqlCreateTable(string $sql): string {
        // Extract the table name.
        if (!preg_match('/\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+`?(\w+)`?/i', $sql, $nm)) {
            return $sql;
        }
        $table = $nm[1];

        // Strip trailing MySQL table options (ENGINE=, DEFAULT CHARSET=, COLLATE=, COMMENT=).
        $sql = preg_replace('/\)\s*(?:ENGINE\s*=\s*\w+|DEFAULT\s+CHARSET\s*=\s*\w+|COLLATE\s*=?\s*\w+|COMMENT\s*=\s*\'[^\']*\'|\s)+\s*;?\s*$/is', ')', $sql);

        // Remove trailing INDEX … (…) entries (must come before UNIQUE KEY rewrite to
        // avoid matching "UNIQUE INDEX").
        $sql = preg_replace('/,\s*(?:KEY|INDEX)\s+\w+\s*\([^)]+\)/i', '', $sql);

        // UNIQUE KEY name (cols) → CONSTRAINT name UNIQUE (cols)
        $sql = preg_replace('/\bUNIQUE\s+KEY\s+(\w+)\s*\(([^)]+)\)/i', 'CONSTRAINT $1 UNIQUE ($2)', $sql);

        // ENUM(…) → NVARCHAR(50)
        $sql = preg_replace('/\bENUM\s*\([^)]*\)/i', 'NVARCHAR(50)', $sql);

        // TEXT → NVARCHAR(MAX)  (as a data type – word boundary avoids false matches)
        $sql = preg_replace('/\bTEXT\b(?!\s*\()/i', 'NVARCHAR(MAX)', $sql);

        // AUTO_INCREMENT PRIMARY KEY → IDENTITY(1,1) PRIMARY KEY
        $sql = preg_replace('/\bAUTO_INCREMENT\b/i', 'IDENTITY(1,1)', $sql);

        // BOOLEAN → BIT
        $sql = preg_replace('/\bBOOLEAN\b/i', 'BIT', $sql);

        // TINYINT(1) → BIT
        $sql = preg_replace('/\bTINYINT\s*\(\s*1\s*\)/i', 'BIT', $sql);

        // TIMESTAMP → DATETIME
        $sql = preg_replace('/\bTIMESTAMP\b/i', 'DATETIME', $sql);

        // CURRENT_TIMESTAMP → GETDATE()
        $sql = preg_replace('/\bCURRENT_TIMESTAMP\b/i', 'GETDATE()', $sql);

        // DEFAULT TRUE → DEFAULT 1,  DEFAULT FALSE → DEFAULT 0
        $sql = preg_replace('/\bDEFAULT\s+TRUE\b/i',  'DEFAULT 1', $sql);
        $sql = preg_replace('/\bDEFAULT\s+FALSE\b/i', 'DEFAULT 0', $sql);

        // Remove ON UPDATE … clauses (not supported in SQL Server column definitions).
        // The value may be a bare keyword (CURRENT_TIMESTAMP) or a function call
        // like NOW() / GETDATE() – so we match an identifier followed by an optional
        // parenthesised argument list to avoid leaving stray ')' characters behind.
        $sql = preg_replace('/\s+ON\s+UPDATE\s+\w+\s*(?:\([^)]*\))?/i', '', $sql);

        // Rewrite CREATE TABLE IF NOT EXISTS tbl → IF OBJECT_ID guard
        $sql = preg_replace(
            '/\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+`?(\w+)`?/i',
            "IF OBJECT_ID(N'$1', 'U') IS NULL CREATE TABLE $1",
            $sql
        );

        return $sql;
    }

    /**
     * Replace FIELD(expr, 'v1', 'v2', ...) with a CASE WHEN equivalent.
     * Uses a character-level balanced-parentheses scan so nested function calls
     * inside FIELD arguments are handled correctly.
     */
    private static function _transformFieldCalls(string $sql): string {
        $out    = '';
        $len    = strlen($sql);
        $offset = 0;

        while (($pos = stripos($sql, 'FIELD(', $offset)) !== false) {
            // Make sure 'FIELD' is a word boundary (not e.g. "INFIELD(")
            if ($pos > 0 && (ctype_alnum($sql[$pos - 1]) || $sql[$pos - 1] === '_')) {
                $out   .= substr($sql, $offset, $pos - $offset + 6);
                $offset = $pos + 6;
                continue;
            }

            // Copy everything up to (but not including) 'FIELD('
            $out .= substr($sql, $offset, $pos - $offset);

            // Walk past 'FIELD(' to find the matching ')'
            $start  = $pos + 6; // first char after '('
            $depth  = 1;
            $inStr  = false;
            $strCh  = '';
            $i      = $start;
            while ($i < $len && $depth > 0) {
                $ch = $sql[$i];
                if ($inStr) {
                    if ($ch === $strCh) $inStr = false;
                    $i++;
                    continue;
                }
                if ($ch === "'" || $ch === '"') {
                    $inStr = true; $strCh = $ch; $i++; continue;
                }
                if ($ch === '(') { $depth++; $i++; continue; }
                if ($ch === ')') { $depth--; if ($depth === 0) break; $i++; continue; }
                $i++;
            }
            // $i now points at the closing ')'
            $inner = substr($sql, $start, $i - $start);

            // Split inner by comma (respecting quoted strings and nested parens)
            $args = [];
            $cur  = '';
            $d    = 0; $inS = false; $sC = '';
            for ($j = 0; $j < strlen($inner); $j++) {
                $c = $inner[$j];
                if ($inS) {
                    $cur .= $c;
                    if ($c === $sC) $inS = false;
                    continue;
                }
                if ($c === "'" || $c === '"') { $inS = true; $sC = $c; $cur .= $c; continue; }
                if ($c === '(') { $d++; $cur .= $c; continue; }
                if ($c === ')') { $d--; $cur .= $c; continue; }
                if ($c === ',' && $d === 0) { $args[] = trim($cur); $cur = ''; continue; }
                $cur .= $c;
            }
            if ($cur !== '') $args[] = trim($cur);

            if (count($args) >= 2) {
                $col   = array_shift($args);
                $cases = '';
                foreach ($args as $idx => $v) {
                    $cases .= " WHEN $v THEN " . ($idx + 1);
                }
                $else  = count($args) + 1;
                $out  .= "CASE $col $cases ELSE $else END";
            } else {
                // Not enough args — leave unchanged
                $out .= "FIELD($inner)";
            }

            $offset = $i + 1; // skip past ')'
        }

        $out .= substr($sql, $offset);
        return $out;
    }

    public function query(string $sql) {
        $sql = self::transformSql($sql);
        try {
            $stmt = $this->pdo->query($sql);
            if ($stmt === false) {
                $info = $this->pdo->errorInfo();
                $this->lastError = $info[2] ?? 'Unknown PDO error';
                return false;
            }
            $this->lastRowCount = $stmt->rowCount();
            try { $lid = $this->pdo->lastInsertId(); if ($lid) $this->lastInsertId = (int)$lid; } catch (Throwable $e) {}
            return new MysqliPdoResult($stmt);
        } catch (Throwable $e) {
            $this->lastError = $e->getMessage();
            error_log("MysqliPdoConn::query error: " . $e->getMessage() . " | SQL: " . $sql);
            return false;
        }
    }

    public function prepare(string $sql): MysqliPdoStmt {
        return new MysqliPdoStmt($this->pdo, $sql, $this);
    }

    public function real_escape_string(string $str): string {
        return str_replace("'", "''", $str);
    }

    public function begin_transaction(int $flags = 0): bool {
        $this->in_transaction = true;
        return $this->pdo->beginTransaction();
    }

    public function commit(): bool {
        $this->in_transaction = false;
        return $this->pdo->commit();
    }

    public function rollback(): bool {
        $this->in_transaction = false;
        return $this->pdo->rollBack();
    }

    public function set_charset(string $charset): bool { return true; }
    public function ping(): bool { return true; }
    public function close(): void { }

    /** Returns true when the underlying PDO driver is SQL Server (sqlsrv / odbc). */
    public function isMsSql(): bool {
        try {
            $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
            return in_array(strtolower($driver), ['sqlsrv', 'odbc'], true);
        } catch (Throwable $e) {
            return false;
        }
    }

    public function __get(string $name) {
        switch ($name) {
            case 'insert_id':      return $this->lastInsertId;
            case 'affected_rows':  return $this->lastRowCount;
            case 'error':          return $this->lastError;
            case 'errno':          return $this->lastErrno;
            case 'connect_error':  return null;
        }
        return null;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build the PDO connection — Windows Auth when user/pass are empty
// ─────────────────────────────────────────────────────────────────────────────
$cfg = Config::get();

$server  = $cfg['db_host'];   // MANAGEENGINE\SQLEXPRESS
$dbName  = $cfg['db_name'];   // switchdb
$dbUser  = $cfg['db_user'];   // '' → Windows Auth
$dbPass  = $cfg['db_pass'];   // '' → Windows Auth

$dsn = "sqlsrv:Server={$server};Database={$dbName};TrustServerCertificate=1";

// Check that the sqlsrv PDO driver is installed before attempting to connect.
if (!in_array('sqlsrv', PDO::getAvailableDrivers())) {
    ob_end_clean();
    header('Content-Type: application/json');
    error_log("Database connection failed: pdo_sqlsrv driver not available.");
    die(json_encode([
        "success" => false,
        "error"   => "PHP pdo_sqlsrv surucusu yuklu degil. php.ini dosyasinda extension=php_pdo_sqlsrv.dll satirini etkinlestirin ve Apache/PHP yi yeniden baslatın."
    ]));
}

// PDO::SQLSRV_ATTR_ENCODING is only defined when pdo_sqlsrv is loaded.
// Build the options array dynamically to avoid a fatal error if the constant
// is missing (e.g. opcode cache loaded before the extension was enabled).
$pdoOptions = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];
if (defined('PDO::SQLSRV_ATTR_ENCODING') && defined('PDO::SQLSRV_ENCODING_UTF8')) {
    $pdoOptions[PDO::SQLSRV_ATTR_ENCODING] = PDO::SQLSRV_ENCODING_UTF8;
}

try {
    $pdo = new PDO(
        $dsn,
        ($dbUser === '') ? null : $dbUser,
        ($dbPass === '') ? null : $dbPass,
        $pdoOptions
    );
} catch (PDOException $e) {
    ob_end_clean();
    header('Content-Type: application/json');
    $detail = $e->getMessage();
    error_log("Database connection failed: " . $detail);

    // Provide an actionable hint for the most common failure: Windows Auth from
    // the Apache service account (NT AUTHORITY\SYSTEM) being rejected by SQL Server.
    $hint = '';
    if (stripos($detail, 'Login failed') !== false
        || stripos($detail, 'cannot open database') !== false
        || stripos($detail, 'Access denied') !== false
    ) {
        $hint = ' Apache servis hesabinin (NT AUTHORITY\\SYSTEM) SQL Server erisimi olmayabilir. '
              . 'setup.bat i yonetici olarak tekrar calistirin ya da SQL Server da manuel login tanimlayın.';
    }

    die(json_encode([
        "success" => false,
        "error"   => "Veritabani baglantisi basarisiz." . $hint
    ]));
}

$conn = new MysqliPdoConn($pdo);

/**
 * Load SNMPv3 credentials for a given switch IP from config.yml.
 *
 * Used as a fallback when the snmp_devices table has no entry for a switch
 * (e.g. the Python SNMP worker has not yet run a successful poll for it).
 *
 * Returns an array with keys:
 *   ip_address, snmp_version, snmp_v3_username, snmp_v3_auth_protocol,
 *   snmp_v3_auth_password, snmp_v3_priv_protocol, snmp_v3_priv_password
 * or null if credentials cannot be found.
 *
 * @param string $switchIp  IP address from the switches table (s.ip)
 * @return array|null
 */
function getSnmpCredsFromConfig(string $switchIp): ?array {
    $cfgFile = __DIR__ . '/snmp_worker/config/config.yml';
    if (!$switchIp || !file_exists($cfgFile)) {
        return null;
    }

    $content = file_get_contents($cfgFile);
    $escapedIp = preg_quote($switchIp, '/');

    // Pattern 1: per-switch snmp_v3 block (preferred — switch may have unique credentials)
    //   - name: "SW31-RUBY"
    //     host: "172.18.1.218"
    //     ...
    //     snmp_v3:
    //       username: "snmpuser"
    //       auth_protocol: "SHA"
    //       auth_password: "AuthPass123!"
    //       priv_protocol: "AES"
    //       priv_password: "PrivPass123!"
    $perSwitchPattern =
        '/host:\s*"?' . $escapedIp . '"?.*?' .
        'snmp_v3:\s*\n\s+username:\s*"([^"]+)"\s+' .
        'auth_protocol:\s*"([^"]+)"\s+' .
        'auth_password:\s*"([^"]+)"\s+' .
        'priv_protocol:\s*"([^"]+)"\s+' .
        'priv_password:\s*"([^"]+)"/s';

    if (preg_match($perSwitchPattern, $content, $m)) {
        // Extract engine_id scoped to this switch's block only (avoid matching another switch)
        $engineId = '';
        $blockBoundaryPattern =
            '/host:\s*"?' . $escapedIp . '"?(.*?)(?=\n  - name:|\n[a-z_]+:|\Z)/s';
        if (preg_match($blockBoundaryPattern, $content, $bm)) {
            if (preg_match('/engine_id:\s*"([^"]+)"/', $bm[1], $em)) {
                $engineId = $em[1];
            }
        }
        return [
            'ip_address'            => $switchIp,
            'snmp_version'          => '3',
            'snmp_v3_username'      => $m[1],
            'snmp_v3_auth_protocol' => $m[2],
            'snmp_v3_auth_password' => $m[3],
            'snmp_v3_priv_protocol' => $m[4],
            'snmp_v3_priv_password' => $m[5],
            'snmp_engine_id'        => $engineId,
        ];
    }

    // Pattern 2: global snmp section (fallback — all switches share one credential set)
    //   snmp:
    //     version: "3"
    //     username: "snmpuser"
    //     auth_protocol: "SHA"
    //     auth_password: "AuthPass123"
    //     priv_protocol: "AES"
    //     priv_password: "PrivPass123"
    $globalPattern =
        '/snmp:\s+version:\s*"3"\s+' .
        'username:\s*"([^"]+)"\s+' .
        'auth_protocol:\s*"([^"]+)"\s+' .
        'auth_password:\s*"([^"]+)"\s+' .
        'priv_protocol:\s*"([^"]+)"\s+' .
        'priv_password:\s*"([^"]+)"/s';

    if (preg_match($globalPattern, $content, $m)) {
        return [
            'ip_address'            => $switchIp,
            'snmp_version'          => '3',
            'snmp_v3_username'      => $m[1],
            'snmp_v3_auth_protocol' => $m[2],
            'snmp_v3_auth_password' => $m[3],
            'snmp_v3_priv_protocol' => $m[4],
            'snmp_v3_priv_password' => $m[5],
        ];
    }

    return null;
}
?>
