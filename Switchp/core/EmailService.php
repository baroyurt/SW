<?php
/**
 * EmailService — shared SMTP mailer for the CHAMADA application.
 *
 * Consolidates the duplicate SMTP socket-stream code that was previously
 * copy-pasted across export_excel.php, device_import_api.php,
 * mac_history_cleanup_api.php, and admin_snmp_config.php.
 *
 * Supports:
 *   • Port 465 — implicit TLS (SSL)
 *   • Port 587 — STARTTLS upgrade
 * Auth: AUTH LOGIN (Base64 username / password)
 *
 * Usage:
 *   // Send using credentials from config.yml (+ env-var overrides)
 *   EmailService::send('Subject', $htmlBody);
 *
 *   // Send using explicit credentials (e.g. test-email in admin UI)
 *   EmailService::sendWith($host, $port, $user, $pass, $from, [$to], 'Subject', $html);
 */

require_once __DIR__ . '/ConfigReader.php';
require_once __DIR__ . '/email_template.php';

class EmailService
{
    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Send an email using SMTP credentials from config.yml.
     * Returns true on success, false on failure (or when email is disabled).
     *
     * @param string $subject  Plain-text subject line.
     * @param string $htmlBody Full HTML body (will be text-stripped automatically).
     */
    public static function send(string $subject, string $htmlBody): bool
    {
        $cfg = ConfigReader::getSmtpConfig();
        if ($cfg === null) {
            return false;
        }

        return self::sendWith(
            $cfg['smtp_host'],
            $cfg['smtp_port'],
            $cfg['smtp_user'],
            $cfg['smtp_password'],
            $cfg['from_address'],
            $cfg['to_addresses'],
            $subject,
            $htmlBody
        );
    }

    /**
     * Send an email with explicit credentials and recipient list.
     * Returns an associative result array:
     *   ['success' => bool, 'message'|'error' => string]
     *
     * When called from application code you can also use the simpler
     * EmailService::send() wrapper which reads credentials from config.
     *
     * @param string   $host
     * @param int      $port
     * @param string   $user
     * @param string   $pass
     * @param string   $from
     * @param string[] $toList  One or more recipient addresses.
     * @param string   $subject
     * @param string   $htmlBody
     * @return array{success:bool,message?:string,error?:string}
     */
    public static function sendWith(
        string $host,
        int    $port,
        string $user,
        string $pass,
        string $from,
        array  $toList,
        string $subject,
        string $htmlBody
    ): array {
        if (empty($toList)) {
            return ['success' => false, 'error' => 'Alıcı adresi belirtilmedi.'];
        }

        $boundary = md5(uniqid((string)mt_rand(), true));
        $plainBody = strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $htmlBody));

        $message = "MIME-Version: 1.0\r\n"
            . "Content-Type: multipart/alternative; boundary=\"{$boundary}\"\r\n\r\n"
            . "--{$boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
            . $plainBody . "\r\n"
            . "--{$boundary}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n"
            . $htmlBody . "\r\n"
            . "--{$boundary}--\r\n";

        $timeout          = 15;
        $useImplicitTLS   = ($port === 465);
        $proto            = $useImplicitTLS ? 'ssl' : 'tcp';
        $sslVerify        = (bool)(getenv('SMTP_SSL_VERIFY') ?: false);

        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer'       => $sslVerify,
                'verify_peer_name'  => $sslVerify,
                'allow_self_signed' => !$sslVerify,
            ],
        ]);

        try {
            $sock = @stream_socket_client(
                "{$proto}://{$host}:{$port}",
                $errno,
                $errstr,
                $timeout,
                STREAM_CLIENT_CONNECT,
                $ctx
            );
            if (!$sock) {
                return ['success' => false, 'error' => "SMTP bağlantısı kurulamadı: {$errstr} ({$errno})"];
            }
            stream_set_timeout($sock, $timeout);

            /** Read full multi-line SMTP response; returns trimmed last response. */
            $read = static function () use ($sock): string {
                $buf = '';
                while (($line = fgets($sock, 1024)) !== false) {
                    $buf .= $line;
                    if (isset($line[3]) && $line[3] === ' ') {
                        break;
                    }
                }
                return trim($buf);
            };

            $greeting = $read();
            if (substr($greeting, 0, 3) !== '220') {
                fclose($sock);
                return ['success' => false, 'error' => "Beklenmeyen SMTP greeting: {$greeting}"];
            }

            fwrite($sock, "EHLO " . gethostname() . "\r\n");
            $read();

            // STARTTLS for port 587
            if (!$useImplicitTLS) {
                fwrite($sock, "STARTTLS\r\n");
                $r = $read();
                if (substr($r, 0, 3) !== '220') {
                    fclose($sock);
                    return ['success' => false, 'error' => "STARTTLS reddedildi: {$r}"];
                }
                if (!stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    fclose($sock);
                    return ['success' => false, 'error' => 'TLS el sıkışması başarısız.'];
                }
                fwrite($sock, "EHLO " . gethostname() . "\r\n");
                $read();
            }

            // AUTH LOGIN
            fwrite($sock, "AUTH LOGIN\r\n");
            $r = $read();
            if (substr($r, 0, 3) !== '334') {
                fclose($sock);
                return ['success' => false, 'error' => "AUTH LOGIN desteklenmiyor: {$r}"];
            }
            fwrite($sock, base64_encode($user) . "\r\n");
            $read();
            fwrite($sock, base64_encode($pass) . "\r\n");
            $r = $read();
            if (substr($r, 0, 3) !== '235') {
                fclose($sock);
                return ['success' => false, 'error' => "SMTP kimlik doğrulama başarısız: {$r}"];
            }

            // Envelope
            fwrite($sock, "MAIL FROM:<{$from}>\r\n");
            $read();
            foreach ($toList as $to) {
                fwrite($sock, "RCPT TO:<{$to}>\r\n");
                $r = $read();
            }

            // Message body
            fwrite($sock, "DATA\r\n");
            $read();
            $encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
            $headers = "From: {$from}\r\n"
                . "To: " . implode(', ', $toList) . "\r\n"
                . "Subject: {$encodedSubject}\r\n"
                . "Date: " . date('r') . "\r\n";
            fwrite($sock, $headers . $message . "\r\n.\r\n");
            $r = $read();
            fwrite($sock, "QUIT\r\n");
            fclose($sock);

            if (substr($r, 0, 3) === '250') {
                return ['success' => true, 'message' => 'E-posta başarıyla gönderildi.'];
            }
            return ['success' => false, 'error' => "SMTP DATA kabul edilmedi: {$r}"];

        } catch (\Throwable $e) {
            error_log('EmailService::sendWith error: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
}
