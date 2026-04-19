<?php
/**
 * ConfigReader — reads CHAMADA SNMP-worker config.yml and exposes values as a
 * typed array.  Credentials can be overridden with environment variables so
 * that the config file stored in the repository never contains real secrets.
 *
 * Environment variable overrides (take precedence over config.yml values):
 *   SMTP_PASSWORD   → email.smtp_password
 *   SMTP_USER       → email.smtp_user
 *   LDAP_PASSWORD   → domain_server.ldap_password
 *
 * Usage:
 *   $cfg = ConfigReader::load();
 *   $smtp = $cfg['email'];   // ['enabled', 'smtp_host', 'smtp_port', ...]
 */

class ConfigReader
{
    /** Absolute path to the SNMP-worker config.yml */
    private static string $defaultConfigPath = '';

    /** Cached parsed result */
    private static ?array $cache = null;

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Parse and return the configuration.  Result is cached for the lifetime
     * of the current request.
     *
     * @param string|null $configPath  Override config file path (for testing).
     * @return array|null  Parsed config or null if the file cannot be read.
     */
    public static function load(?string $configPath = null): ?array
    {
        if ($configPath === null) {
            if (self::$cache !== null) {
                return self::$cache;
            }
            $configPath = self::resolveDefaultPath();
        }

        if (!file_exists($configPath)) {
            return null;
        }

        $raw = @file_get_contents($configPath);
        if ($raw === false || $raw === '') {
            return null;
        }

        $parsed = self::parse($raw);

        // Apply env-var overrides
        if (($v = getenv('SMTP_PASSWORD')) !== false && $v !== '') {
            $parsed['email']['smtp_password'] = $v;
        }
        if (($v = getenv('SMTP_USER')) !== false && $v !== '') {
            $parsed['email']['smtp_user'] = $v;
        }
        if (($v = getenv('LDAP_PASSWORD')) !== false && $v !== '') {
            $parsed['domain_server']['ldap_password'] = $v;
        }

        // Cache only for the default path
        if ($configPath === self::resolveDefaultPath()) {
            self::$cache = $parsed;
        }

        return $parsed;
    }

    /**
     * Return the SMTP configuration block ready for use by EmailService.
     * Returns null when email is disabled or the config cannot be read.
     *
     * @return array{smtp_host:string,smtp_port:int,smtp_user:string,smtp_password:string,from_address:string,to_addresses:string[]}|null
     */
    public static function getSmtpConfig(): ?array
    {
        $cfg = self::load();
        if ($cfg === null) {
            return null;
        }

        $email = $cfg['email'] ?? [];
        if (empty($email['enabled']) || $email['enabled'] === false || $email['enabled'] === 'false') {
            return null;
        }

        $toAddresses = $email['to_addresses'] ?? [];
        if (empty($toAddresses)) {
            return null;
        }

        return [
            'smtp_host'     => $email['smtp_host']     ?? '',
            'smtp_port'     => (int)($email['smtp_port'] ?? 465),
            'smtp_user'     => $email['smtp_user']     ?? '',
            'smtp_password' => $email['smtp_password'] ?? '',
            'from_address'  => $email['from_address']  ?? ($email['smtp_user'] ?? ''),
            'to_addresses'  => array_values(array_filter((array)$toAddresses)),
        ];
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /** Resolve the default config.yml path relative to this file's location. */
    private static function resolveDefaultPath(): string
    {
        if (self::$defaultConfigPath === '') {
            self::$defaultConfigPath = dirname(__DIR__) . '/snmp_worker/config/config.yml';
        }
        return self::$defaultConfigPath;
    }

    /**
     * Minimal YAML parser that handles only the structures present in
     * config.yml (scalars, quoted strings, nested mappings, sequences).
     * A full YAML library is not required.
     */
    private static function parse(string $raw): array
    {
        $result = [];
        $lines  = explode("\n", $raw);
        $stack  = [&$result]; // stack of references for indentation tracking
        $depths = [0];        // corresponding indentation levels

        $prevKey   = null;
        $prevDepth = 0;

        foreach ($lines as $line) {
            // Strip comments and skip blank lines
            $stripped = rtrim($line);
            if (preg_match('/^\s*#/', $stripped) || trim($stripped) === '') {
                continue;
            }

            // Determine indentation
            $indent = strlen($stripped) - strlen(ltrim($stripped));
            $content = ltrim($stripped);

            // Pop stack back to the correct parent level
            while (count($depths) > 1 && $indent <= $depths[count($depths) - 1]) {
                array_pop($stack);
                array_pop($depths);
            }

            $current = &$stack[count($stack) - 1];

            // Sequence item
            if (substr($content, 0, 2) === '- ') {
                $value = self::parseScalar(substr($content, 2));
                if (!is_array($current)) {
                    $current = [];
                }
                $current[] = $value;
                continue;
            }

            // Mapping key
            if (strpos($content, ':') !== false) {
                $colonPos = strpos($content, ':');
                $key      = trim(substr($content, 0, $colonPos));
                $rest     = trim(substr($content, $colonPos + 1));

                // Remove inline comment from value
                if ($rest !== '' && $rest[0] !== '"' && $rest[0] !== "'") {
                    $hashPos = strpos($rest, ' #');
                    if ($hashPos !== false) {
                        $rest = trim(substr($rest, 0, $hashPos));
                    }
                }

                if ($rest === '') {
                    // Nested mapping or sequence follows
                    if (!isset($current[$key]) || !is_array($current[$key])) {
                        $current[$key] = [];
                    }
                    $child = &$current[$key];
                    $stack[]  = &$child;
                    $depths[] = $indent;
                } else {
                    $current[$key] = self::parseScalar($rest);
                }
                continue;
            }

            // Bare sequence item without "- " prefix (shouldn't normally happen but be safe)
            if (substr($content, 0, 1) === '-') {
                $value = self::parseScalar(trim(substr($content, 1)));
                if (!is_array($current)) {
                    $current = [];
                }
                $current[] = $value;
            }
        }

        return $result;
    }

    /** Convert a YAML scalar string to a PHP value. */
    private static function parseScalar(string $raw): mixed
    {
        $raw = trim($raw);

        // Quoted string (single or double)
        if (strlen($raw) >= 2
            && (($raw[0] === '"' && substr($raw, -1) === '"')
                || ($raw[0] === "'" && substr($raw, -1) === "'"))) {
            return substr($raw, 1, -1);
        }

        // Boolean
        if (in_array(strtolower($raw), ['true', 'yes', 'on'], true))  return true;
        if (in_array(strtolower($raw), ['false', 'no', 'off'], true)) return false;

        // Null
        if (in_array(strtolower($raw), ['null', '~', ''], true)) return null;

        // Integer / float
        if (is_numeric($raw)) {
            return strpos($raw, '.') !== false ? (float)$raw : (int)$raw;
        }

        return $raw;
    }
}
