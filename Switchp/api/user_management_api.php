<?php
/**
 * User Management API (admin-only)
 */
header('Content-Type: application/json');

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

// Email address used by the SMTP sender — never add to recipient list
const SNMP_EXCLUDE_EMAIL = 'destek@chamadaprestige.com';

/**
 * Add an email address to the SNMP config to_addresses list.
 * Skips SNMP_EXCLUDE_EMAIL and addresses already present.
 */
function addEmailToSnmpConfig(string $configPath, string $email): void {
    if (!$email || !file_exists($configPath)) return;
    if (strcasecmp($email, SNMP_EXCLUDE_EMAIL) === 0) return;

    $content = file_get_contents($configPath);
    // Already present?
    if (strpos($content, $email) !== false) return;

    // to_addresses block with existing entries
    if (preg_match('/^( {2}to_addresses:\s*\n)((?:[ \t]+- "[^"]*"\s*\n)*)/m', $content, $m)) {
        $newEntry = '    - "' . $email . '"' . "\n";
        $content = str_replace($m[0], $m[1] . $m[2] . $newEntry, $content);
        file_put_contents($configPath, $content);
        return;
    }
    // to_addresses: [] — replace with block
    if (preg_match('/^( {2}to_addresses:\s*\[\])/m', $content, $m)) {
        $content = str_replace($m[0], '  to_addresses:' . "\n" . '    - "' . $email . '"', $content);
        file_put_contents($configPath, $content);
    }
}

/**
 * Remove an email address from the SNMP config to_addresses list.
 */
function removeEmailFromSnmpConfig(string $configPath, string $email): void {
    if (!$email || !file_exists($configPath)) return;
    $content = file_get_contents($configPath);
    // Remove any line that contains exactly this email in a list entry
    $escaped = preg_quote($email, '/');
    $content = preg_replace('/^[ \t]*- "?' . $escaped . '"?[ \t]*\r?\n/m', '', $content);
    file_put_contents($configPath, $content);
}

/**
 * Update an email address in the SNMP config to_addresses list.
 * Removes the old address and adds the new one (unless excluded).
 */
function updateEmailInSnmpConfig(string $configPath, string $oldEmail, string $newEmail): void {
    if ($oldEmail) removeEmailFromSnmpConfig($configPath, $oldEmail);
    if ($newEmail) addEmailToSnmpConfig($configPath, $newEmail);
}

$auth = new Auth($conn);
$auth->requireLogin();
$currentUser = $auth->getUser();

$snmpConfigPath = __DIR__ . '/../snmp_worker/config/config.yml';

if ($currentUser['role'] !== 'admin') {
    echo json_encode(['success' => false, 'error' => 'Yetkisiz erişim']);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    $action = $_GET['action'] ?? '';

    if ($action === 'list') {
        $result = $conn->query("SELECT id, username, full_name, email, role, is_active, created_at, last_login FROM users ORDER BY id ASC");
        $rows = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
        // Cast numeric fields so JavaScript boolean checks work correctly
        $users = array_map(function($u) {
            $u['id']        = (int)$u['id'];
            $u['is_active'] = (int)$u['is_active'];
            return $u;
        }, $rows);
        echo json_encode(['success' => true, 'users' => $users]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Geçersiz işlem']);
    }
    exit;
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true) ?? [];
    $action = $data['action'] ?? '';

    if ($action === 'add') {
        $username  = trim($data['username'] ?? '');
        $fullName  = trim($data['full_name'] ?? '');
        $email     = trim($data['email'] ?? '');
        $role      = in_array($data['role'] ?? '', ['admin', 'user']) ? $data['role'] : 'user';
        $password  = $data['password'] ?? '';

        if (!$username || !$fullName || strlen($password) < 8) {
            echo json_encode(['success' => false, 'error' => 'Kullanıcı adı, ad soyad ve en az 8 karakterli şifre zorunludur']);
            exit;
        }

        if ($email && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(['success' => false, 'error' => 'Geçersiz e-posta adresi']);
            exit;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (username, full_name, email, password, role, is_active) VALUES (?, ?, ?, ?, ?, 1)");
        $stmt->bind_param('sssss', $username, $fullName, $email, $hash, $role);
        if ($stmt->execute()) {
            // Auto-add the new user's email to SNMP to_addresses
            if ($email) addEmailToSnmpConfig($snmpConfigPath, $email);
            echo json_encode(['success' => true, 'id' => $conn->insert_id]);
        } else {
            $err = $conn->errno === 1062 ? 'Bu kullanıcı adı zaten kullanılıyor' : $stmt->error;
            echo json_encode(['success' => false, 'error' => $err]);
        }
        $stmt->close();

    } elseif ($action === 'update') {
        $id       = (int)($data['id'] ?? 0);
        $username = trim($data['username'] ?? '');
        $fullName = trim($data['full_name'] ?? '');
        $email    = trim($data['email'] ?? '');
        $role     = in_array($data['role'] ?? '', ['admin', 'user']) ? $data['role'] : 'user';

        if (!$id || !$username || !$fullName) {
            echo json_encode(['success' => false, 'error' => 'Geçersiz kullanıcı veya kullanıcı adı ve ad soyad zorunludur']);
            exit;
        }
        if ($email && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(['success' => false, 'error' => 'Geçersiz e-posta adresi']);
            exit;
        }

        // Fetch old email for SNMP config sync
        $oldEmail = null;
        $oldRow = $conn->query("SELECT email FROM users WHERE id = " . $id);
        if ($oldRow && ($oldRowData = $oldRow->fetch_assoc())) {
            $oldEmail = $oldRowData['email'] ?? null;
        }

        $stmt = $conn->prepare("UPDATE users SET username = ?, full_name = ?, email = ?, role = ? WHERE id = ?");
        $stmt->bind_param('ssssi', $username, $fullName, $email, $role, $id);
        if ($stmt->execute()) {
            // Sync email change in SNMP to_addresses
            if ($oldEmail !== null && $oldEmail !== $email) {
                updateEmailInSnmpConfig($snmpConfigPath, $oldEmail, $email);
            } elseif ($email && $oldEmail === null) {
                addEmailToSnmpConfig($snmpConfigPath, $email);
            }
            echo json_encode(['success' => true]);
        } else {
            $err = $conn->errno === 1062 ? 'Bu kullanıcı adı zaten kullanılıyor' : $stmt->error;
            echo json_encode(['success' => false, 'error' => $err]);
        }
        $stmt->close();

    } elseif ($action === 'change_password') {
        $id       = (int)($data['id'] ?? 0);
        $password = $data['password'] ?? '';

        if (!$id || strlen($password) < 8) {
            echo json_encode(['success' => false, 'error' => 'Geçersiz kullanıcı veya şifre çok kısa (en az 8 karakter)']);
            exit;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->bind_param('si', $hash, $id);
        if ($stmt->execute() && $stmt->affected_rows > 0) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Kullanıcı bulunamadı veya güncelleme başarısız']);
        }
        $stmt->close();

    } elseif ($action === 'toggle_active') {
        $id        = (int)($data['id'] ?? 0);
        $isActive  = (int)($data['is_active'] ?? 0);

        // Prevent deactivating own account
        if ($id === (int)$currentUser['id'] && $isActive === 0) {
            echo json_encode(['success' => false, 'error' => 'Kendi hesabınızı pasif yapamazsınız']);
            exit;
        }

        $stmt = $conn->prepare("UPDATE users SET is_active = ? WHERE id = ?");
        $stmt->bind_param('ii', $isActive, $id);
        if ($stmt->execute()) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Güncelleme başarısız']);
        }
        $stmt->close();

    } else {
        echo json_encode(['success' => false, 'error' => 'Geçersiz işlem']);
    }
    exit;
}

echo json_encode(['success' => false, 'error' => 'Geçersiz istek metodu']);
?>
