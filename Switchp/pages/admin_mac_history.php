<?php
// MAC Change History - Port bazlı MAC değişim geçmişi
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();
// Release PHP session lock immediately – this page only reads session data.
session_write_close();

$currentUser = $auth->getUser();

// Prevent caching
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Read history from JSON file
$historyFile = __DIR__ . '/../logs/mac_history.json';
$allHistory  = [];

if (file_exists($historyFile)) {
    $fp = fopen($historyFile, 'r');
    if ($fp && flock($fp, LOCK_SH)) {
        $raw = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $allHistory = $decoded;
        }
    } elseif ($fp) {
        fclose($fp);
    }
}

// Build unique switch list for filter
$switches = [];
foreach ($allHistory as $entry) {
    $sw = $entry['switch'] ?? '';
    if ($sw && !in_array($sw, $switches)) {
        $switches[] = $sw;
    }
}
sort($switches);

// Get filter values from query string
$filterSwitch = isset($_GET['switch']) ? trim($_GET['switch']) : '';
$filterMac    = isset($_GET['mac'])    ? strtoupper(trim($_GET['mac'])) : '';

// Apply filters
$history = array_filter($allHistory, function ($entry) use ($filterSwitch, $filterMac) {
    if ($filterSwitch && ($entry['switch'] ?? '') !== $filterSwitch) {
        return false;
    }
    if ($filterMac) {
        $oldMac = strtoupper($entry['old_mac'] ?? '');
        $newMac = strtoupper($entry['new_mac'] ?? '');
        if (strpos($oldMac, $filterMac) === false && strpos($newMac, $filterMac) === false) {
            return false;
        }
    }
    return true;
});

// Ensure array is re-indexed (already newest-first from writeMacHistory)
$history = array_values($history);
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MAC Değişim Geçmişi</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }

        :root {
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #0f172a;
            --dark-light: #1e293b;
            --text: #e2e8f0;
            --text-light: #94a3b8;
            --border: #334155;
        }

        body {
            background: linear-gradient(135deg, var(--dark) 0%, var(--dark-light) 100%);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
        }

        .container { max-width: 1400px; margin: 0 auto; }

        .page-header {
            background: rgba(15,23,42,0.95);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
            margin-bottom: 20px;
            border: 1px solid rgba(56,189,248,0.15);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .page-header h1 {
            color: var(--primary);
            font-size: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .back-btn {
            padding: 10px 20px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: background 0.2s;
        }

        .back-btn:hover { background: var(--primary-dark); }

        .filter-bar {
            background: rgba(15,23,42,0.8);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: flex-end;
        }

        .filter-group { display: flex; flex-direction: column; gap: 6px; }

        .filter-group label { font-size: 12px; color: var(--text-light); font-weight: 500; }

        .filter-input, .filter-select {
            padding: 8px 12px;
            background: var(--dark);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 14px;
            min-width: 200px;
        }

        .filter-btn {
            padding: 9px 20px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: background 0.2s;
        }

        .filter-btn:hover { background: var(--primary-dark); }

        .reset-btn {
            padding: 9px 20px;
            background: transparent;
            color: var(--text-light);
            border: 1px solid var(--border);
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
            text-decoration: none;
        }

        .reset-btn:hover { background: rgba(255,255,255,0.05); color: var(--text); }

        .stats-bar {
            background: rgba(59,130,246,0.1);
            border: 1px solid rgba(59,130,246,0.3);
            border-radius: 10px;
            padding: 12px 20px;
            margin-bottom: 20px;
            display: flex;
            gap: 20px;
            font-size: 14px;
            align-items: center;
        }

        .stats-bar .stat { display: flex; align-items: center; gap: 8px; }
        .stats-bar .stat strong { color: var(--primary); }

        .history-table-wrap {
            background: rgba(15,23,42,0.8);
            border-radius: 12px;
            border: 1px solid var(--border);
            overflow: hidden;
        }

        table { width: 100%; border-collapse: collapse; }

        thead th {
            background: rgba(59,130,246,0.15);
            padding: 14px 16px;
            text-align: left;
            font-size: 12px;
            color: var(--text-light);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border);
        }

        tbody tr { border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s; }
        tbody tr:hover { background: rgba(255,255,255,0.04); }
        tbody tr:last-child { border-bottom: none; }

        td {
            padding: 13px 16px;
            font-size: 14px;
            vertical-align: middle;
        }

        .mac-badge {
            background: rgba(139,92,246,0.2);
            color: #c4b5fd;
            padding: 3px 8px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }

        .port-badge {
            background: rgba(59,130,246,0.2);
            color: var(--primary);
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 13px;
            font-weight: bold;
        }

        .port-badge.old { background: rgba(239,68,68,0.2); color: #fca5a5; }
        .port-badge.new { background: rgba(16,185,129,0.2); color: #6ee7b7; }
        .port-badge.empty { color: var(--text-light); font-style: italic; }

        .action-badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }

        .action-mac_moved         { background: rgba(245,158,11,0.2); color: #fcd34d; }
        .action-device_registered { background: rgba(16,185,129,0.2); color: #6ee7b7; }

        .no-data {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-light);
        }

        .no-data i { font-size: 48px; opacity: 0.3; margin-bottom: 16px; display: block; }

        /* Cleanup button */
        .cleanup-btn {
            padding: 9px 20px;
            background: rgba(239,68,68,0.15);
            color: #fca5a5;
            border: 1px solid rgba(239,68,68,0.4);
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
            margin-left: auto;
        }
        .cleanup-btn:hover { background: rgba(239,68,68,0.3); color: #fff; }

        /* Modal overlay */
        .modal-overlay {
            display: none;
            position: fixed; inset: 0;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal-overlay.active { display: flex; }

        .modal-box {
            background: var(--dark-light);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 30px;
            width: 400px;
            max-width: 95vw;
            box-shadow: 0 20px 60px rgba(0,0,0,0.6);
        }
        .modal-box h2 {
            font-size: 18px;
            color: #fca5a5;
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 18px;
        }
        .modal-box p { font-size: 14px; color: var(--text-light); margin-bottom: 18px; }
        .modal-days-row { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
        .modal-days-row label { font-size: 14px; color: var(--text); white-space: nowrap; }
        .modal-days-input {
            width: 90px;
            padding: 8px 12px;
            background: var(--dark);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 16px;
            text-align: center;
        }
        .modal-password-row { display: flex; flex-direction: column; gap: 6px; margin-bottom: 22px; }
        .modal-password-row label { font-size: 14px; color: var(--text); }
        .modal-password-input {
            width: 100%;
            padding: 8px 12px;
            background: var(--dark);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 14px;
            box-sizing: border-box;
        }
        .modal-password-input:focus { outline: none; border-color: var(--danger); }
        .modal-password-error { font-size: 12px; color: #f87171; display: none; margin-top: 4px; }
        .modal-actions { display: flex; gap: 12px; justify-content: flex-end; }
        .modal-cancel {
            padding: 9px 20px;
            background: transparent;
            color: var(--text-light);
            border: 1px solid var(--border);
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
        }
        .modal-cancel:hover { background: rgba(255,255,255,0.05); }
        .modal-confirm {
            padding: 9px 20px;
            background: var(--danger);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .modal-confirm:hover { background: #dc2626; }
        .modal-confirm:disabled { opacity: 0.6; cursor: not-allowed; }

        /* Toast */
        .toast {
            position: fixed;
            bottom: 30px; right: 30px;
            padding: 14px 22px;
            border-radius: 10px;
            font-size: 14px;
            color: white;
            z-index: 2000;
            opacity: 0;
            transition: opacity 0.3s;
            pointer-events: none;
            max-width: 350px;
        }
        .toast.show { opacity: 1; }
        .toast.success { background: rgba(16,185,129,0.9); border: 1px solid #10b981; }
        .toast.error   { background: rgba(239,68,68,0.9);  border: 1px solid #ef4444; }
    </style>
</head>
<body>
<div class="container">

    <div class="page-header">
        <h1><i class="fas fa-history"></i> MAC Değişim Geçmişi</h1>
        <a href="admin.php" class="back-btn">
            <i class="fas fa-arrow-left"></i> Yönetim Paneli
        </a>
    </div>

    <!-- Filter Bar -->
    <form method="GET" action="">
        <div class="filter-bar">
            <div class="filter-group">
                <label>Switch Filtresi</label>
                <select name="switch" class="filter-select">
                    <option value="">— Tüm Switchler —</option>
                    <?php foreach ($switches as $sw): ?>
                        <option value="<?= htmlspecialchars($sw) ?>"
                            <?= $filterSwitch === $sw ? 'selected' : '' ?>>
                            <?= htmlspecialchars($sw) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="filter-group">
                <label>MAC Adresi Ara</label>
                <input type="text" name="mac" class="filter-input"
                       placeholder="Örn: D0:AD:08"
                       value="<?= htmlspecialchars($filterMac) ?>">
            </div>
            <button type="submit" class="filter-btn">
                <i class="fas fa-search"></i> Filtrele
            </button>
            <a href="admin_mac_history.php" class="reset-btn">
                <i class="fas fa-times"></i> Temizle
            </a>
            <button type="button" class="cleanup-btn" onclick="openCleanupModal()">
                <i class="fas fa-trash-alt"></i> Eski Kayıtları Sil
            </button>
        </div>
    </form>

    <!-- Cleanup Modal -->
    <div class="modal-overlay" id="cleanupModal">
        <div class="modal-box">
            <h2><i class="fas fa-trash-alt"></i> Eski Kayıtları Temizle</h2>
            <p>Belirttiğiniz günden daha eski tüm MAC geçmiş kayıtları <strong>kalıcı olarak silinir</strong>.</p>
            <div class="modal-days-row">
                <label for="cleanupDays">Son kaç günü koru?</label>
                <input type="number" id="cleanupDays" class="modal-days-input" value="7" min="1" max="9999">
                <span style="color:var(--text-light); font-size:14px;">gün</span>
            </div>
            <div class="modal-password-row">
                <label for="cleanupPassword">Onay için şifrenizi girin:</label>
                <input type="password" id="cleanupPassword" class="modal-password-input" placeholder="Şifreniz…" autocomplete="current-password">
                <span class="modal-password-error" id="cleanupPasswordError">Şifre hatalı. Lütfen tekrar deneyin.</span>
            </div>
            <div class="modal-actions">
                <button type="button" class="modal-cancel" onclick="closeCleanupModal()">İptal</button>
                <button type="button" class="modal-confirm" id="cleanupConfirmBtn" onclick="runCleanup()">
                    <i class="fas fa-trash-alt"></i> Sil
                </button>
            </div>
        </div>
    </div>

    <!-- Toast notification -->
    <div class="toast" id="toast"></div>

    <!-- Stats -->
    <div class="stats-bar">
        <div class="stat">
            <i class="fas fa-list" style="color:var(--primary)"></i>
            <span>Toplam: <strong><?= count($history) ?></strong></span>
        </div>
        <?php if ($filterSwitch || $filterMac): ?>
        <div class="stat">
            <i class="fas fa-filter" style="color:var(--warning)"></i>
            <span>Filtre aktif</span>
        </div>
        <?php endif; ?>
        <div class="stat" style="margin-left:auto; font-size:12px; color:var(--text-light);">
            <i class="fas fa-database"></i> Toplam Kayıt: <?= count($allHistory) ?>
        </div>
    </div>

    <!-- History Table -->
    <div class="history-table-wrap">
        <?php if (empty($history)): ?>
            <div class="no-data">
                <i class="fas fa-inbox"></i>
                <p>Kayıt bulunamadı.</p>
            </div>
        <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>Tarih / Saat</th>
                    <th>Switch</th>
                    <th>Switch IP</th>
                    <th>Eski Port</th>
                    <th>Yeni Port</th>
                    <th>Eski MAC</th>
                    <th>Yeni MAC</th>
                    <th>İşlem</th>
                    <th>Onaylayan</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($history as $entry): ?>
                <tr>
                    <td><?= htmlspecialchars($entry['timestamp'] ?? '-') ?></td>
                    <td><?= htmlspecialchars($entry['switch']    ?? '-') ?></td>
                    <td><?= ($entry['switch_ip'] ?? '') !== '' ? '***' : '-' ?></td>
                    <td>
                        <?php if (!empty($entry['old_port'])): ?>
                            <span class="port-badge old">Port <?= htmlspecialchars($entry['old_port']) ?></span>
                        <?php else: ?>
                            <span class="port-badge empty">—</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if (!empty($entry['new_port'])): ?>
                            <span class="port-badge new">Port <?= htmlspecialchars($entry['new_port']) ?></span>
                        <?php else: ?>
                            <span class="port-badge empty">—</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if (!empty($entry['old_mac'])): ?>
                            <span class="mac-badge"><?= htmlspecialchars($entry['old_mac']) ?></span>
                        <?php else: ?>
                            <span style="color:var(--text-light)">—</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if (!empty($entry['new_mac'])): ?>
                            <span class="mac-badge"><?= htmlspecialchars($entry['new_mac']) ?></span>
                        <?php else: ?>
                            <span style="color:var(--text-light)">—</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php
                            $action = $entry['action'] ?? '';
                            $labels = [
                                'mac_moved'          => 'MAC Taşındı',
                                'device_registered'  => 'Cihaz Kaydedildi',
                            ];
                            $label = $labels[$action] ?? htmlspecialchars($action);
                        ?>
                        <span class="action-badge action-<?= htmlspecialchars($action) ?>">
                            <?= htmlspecialchars($label) ?>
                        </span>
                    </td>
                    <td><?= htmlspecialchars($entry['approved_by'] ?? '-') ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>

</div>

<script>
function openCleanupModal() {
    document.getElementById('cleanupModal').classList.add('active');
    document.getElementById('cleanupPassword').value = '';
    document.getElementById('cleanupPasswordError').style.display = 'none';
    document.getElementById('cleanupDays').focus();
}

function closeCleanupModal() {
    document.getElementById('cleanupModal').classList.remove('active');
    document.getElementById('cleanupPassword').value = '';
    document.getElementById('cleanupPasswordError').style.display = 'none';
}

// Close on backdrop click
document.getElementById('cleanupModal').addEventListener('click', function(e) {
    if (e.target === this) closeCleanupModal();
});

// Allow Enter key inside password field to trigger cleanup
document.getElementById('cleanupPassword').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') runCleanup();
});

function showToast(msg, type) {
    var t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast ' + type + ' show';
    setTimeout(function() { t.classList.remove('show'); }, 4000);
}

function runCleanup() {
    var days = parseInt(document.getElementById('cleanupDays').value, 10);
    if (!days || days < 1) {
        showToast('Geçerli bir gün sayısı giriniz.', 'error');
        return;
    }

    var password = document.getElementById('cleanupPassword').value;
    if (!password) {
        document.getElementById('cleanupPasswordError').textContent = 'Şifre boş olamaz.';
        document.getElementById('cleanupPasswordError').style.display = 'block';
        document.getElementById('cleanupPassword').focus();
        return;
    }

    var btn = document.getElementById('cleanupConfirmBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Doğrulanıyor…';
    document.getElementById('cleanupPasswordError').style.display = 'none';

    // Step 1: Verify password
    fetch('../api/verify_password_api.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: password })
    })
    .then(function(r) { return r.json(); })
    .then(function(v) {
        if (!v.success) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-trash-alt"></i> Sil';
            document.getElementById('cleanupPasswordError').textContent = v.message || 'Şifre hatalı.';
            document.getElementById('cleanupPasswordError').style.display = 'block';
            document.getElementById('cleanupPassword').focus();
            document.getElementById('cleanupPassword').select();
            return;
        }

        // Step 2: Password ok — proceed with deletion
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Siliniyor…';

        var fd = new FormData();
        fd.append('days', days);

        fetch('../api/mac_history_cleanup_api.php', { method: 'POST', body: fd })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-trash-alt"></i> Sil';
                closeCleanupModal();
                if (data.success) {
                    showToast(data.message, 'success');
                    setTimeout(function() { window.location.reload(); }, 1500);
                } else {
                    showToast(data.message || 'Bir hata oluştu.', 'error');
                }
            })
            .catch(function() {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-trash-alt"></i> Sil';
                showToast('Sunucu hatası. Lütfen tekrar deneyin.', 'error');
            });
    })
    .catch(function() {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-trash-alt"></i> Sil';
        showToast('Sunucu hatası. Lütfen tekrar deneyin.', 'error');
    });
}
</script>
</body>
</html>
