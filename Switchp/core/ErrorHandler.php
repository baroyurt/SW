<?php
// core/ErrorHandler.php
// Centralized error/exception handling and file logging.

require_once __DIR__ . '/../config.php';

class ErrorHandler {
    public static function init() {
        $cfg = Config::get();
        ini_set('log_errors', 1);
        ini_set('error_log', $cfg['log_file']);

        set_error_handler(function($errno, $errstr, $errfile, $errline) use ($cfg) {
            $msg = sprintf("PHP Error [%d]: %s in %s on line %d", $errno, $errstr, $errfile, $errline);
            error_log($msg);
            if ($cfg['env'] === 'development') {
                header('Content-Type: application/json');
                echo json_encode(['status' => 'error', 'message' => $msg]);
            } else {
                header('Content-Type: application/json');
                echo json_encode(['status' => 'error', 'message' => 'Internal server error']);
            }
            exit;
        });

        set_exception_handler(function($e) use ($cfg) {
            $msg = "Uncaught Exception: ".$e->getMessage()." in ".$e->getFile().":".$e->getLine();
            error_log($msg."\n".$e->getTraceAsString());
            if ($cfg['env'] === 'development') {
                header('Content-Type: application/json');
                echo json_encode(['status' => 'error', 'message' => $msg, 'trace' => $e->getTraceAsString()]);
            } else {
                header('Content-Type: application/json');
                echo json_encode(['status' => 'error', 'message' => 'Internal server error']);
            }
            exit;
        });

        register_shutdown_function(function() use ($cfg) {
            $err = error_get_last();
            if ($err) {
                $msg = "Fatal error: ".print_r($err, true);
                error_log($msg);
                if ($cfg['env'] === 'development') {
                    header('Content-Type: application/json');
                    echo json_encode(['status' => 'error', 'message' => $msg]);
                }
            }
        });
    }
}