<?php
/**
 * report_flapping.php — Up/Down Döngüsü Raporu
 * Son 1 saat içinde 2 veya daha fazla kez durum değişikliği yaşayan portları listeler.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();
session_write_close();

header('Cache-Control: no-cache, no-store, must-revalidate');

// ── Döngü yapan portlar (son 1 saat, ≥2 status_changed) ─────────────────────
// db.php otomatik olarak NOW() → GETDATE() ve DATE_SUB → DATEADD dönüşümü yapar
$sql = "
    SELECT
        pch.device_id,
        pch.port_number,
        sd.name        AS switch_name,
        sd.ip_address,
        COUNT(pch.id)                AS change_count,
        MIN(pch.change_timestamp)    AS first_change,
        MAX(pch.change_timestamp)    AS last_change,
        psd.port_alias               AS alias,
        psd.vlan_id
    FROM port_change_history pch
    LEFT JOIN snmp_devices sd  ON sd.id  = pch.device_id
    LEFT JOIN port_status_data psd ON psd.device_id = pch.device_id
                                   AND psd.port_number = pch.port_number
    WHERE pch.change_type = 'status_changed'
      AND pch.change_timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    GROUP BY pch.device_id, pch.port_number, sd.name, sd.ip_address,
             psd.port_alias, psd.vlan_id
    HAVING COUNT(pch.id) >= 2
    ORDER BY COUNT(pch.id) DESC, MAX(pch.change_timestamp) DESC
";
$result = $conn->query($sql);
$ports  = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
$cnt    = count($ports);

// Toplam değişim sayısı
$totalChanges = array_sum(array_column($ports, 'change_count'));
$maxChanges   = $ports ? (int)$ports[0]['change_count'] : 1;
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Up/Down Döngüsü</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
<style>
    html { zoom: 0.95; }
    :root {
        --primary:      #3b82f6;
        --success:      #10b981;
        --warning:      #f59e0b;
        --danger:       #ef4444;
        --dark:         #0f172a;
        --dark-light:   #1e293b;
        --text:         #e2e8f0;
        --text-light:   #94a3b8;
        --border:       #334155;
    }
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:var(--dark); color:var(--text); padding:20px; }
    .container { max-width:1300px; margin:0 auto; }

    .header { background:var(--dark-light); padding:20px 24px; border-radius:12px; border:1px solid var(--border); margin-bottom:20px; display:flex; align-items:center; gap:16px; }
    .header-icon { font-size:32px; color:var(--danger); }
    .header h1  { color:var(--danger); font-size:20px; margin-bottom:4px; }
    .header p   { color:var(--text-light); font-size:12px; line-height:1.5; }

    .section-title { font-size:12px; text-transform:uppercase; letter-spacing:1px; color:var(--text-light); margin-bottom:12px; display:flex; align-items:center; gap:8px; }
    .section-title i { color:var(--primary); }

    .stats-bar { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:20px; }
    .stat-card { background:var(--dark-light); padding:18px; border-radius:10px; border:1px solid var(--border); text-align:center; }
    .stat-card .num   { font-size:28px; font-weight:700; margin-bottom:4px; }
    .stat-card .label { font-size:11px; color:var(--text-light); text-transform:uppercase; letter-spacing:1px; }
    .stat-card.red    .num { color:var(--danger); }
    .stat-card.orange .num { color:var(--warning); }
    .stat-card.info   .num { color:var(--primary); }

    .toolbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
    .search-box { position:relative; flex:1; min-width:200px; }
    .search-box i { position:absolute; left:10px; top:50%; transform:translateY(-50%); color:var(--text-light); font-size:12px; }
    .search-box input { width:100%; padding:8px 10px 8px 32px; background:var(--dark-light); border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:13px; outline:none; }
    .search-box input:focus { border-color:var(--primary); }

    .table-wrap { background:var(--dark-light); border-radius:12px; border:1px solid var(--border); overflow:hidden; }
    table { width:100%; border-collapse:collapse; }
    thead th { background:#2b0d0d; padding:11px 15px; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:var(--text-light); text-align:left; border-bottom:1px solid var(--border); white-space:nowrap; cursor:pointer; user-select:none; }
    thead th:hover { color:var(--danger); }
    thead th .sort-icon { margin-left:4px; opacity:0.4; font-size:10px; }
    thead th.sorted .sort-icon { opacity:1; color:var(--danger); }
    tbody tr { border-bottom:1px solid #1e2a3a; transition:background 0.15s; }
    tbody tr:last-child { border-bottom:none; }
    tbody tr:hover { background:#2a1a1a; }
    tbody td { padding:10px 15px; font-size:13px; }

    .badge-flap { display:inline-flex; align-items:center; gap:5px; padding:4px 12px; border-radius:20px; font-size:12px; font-weight:700; }
    .flap-high   { background:#2b0d0d; color:#fca5a5; border:1px solid #b91c1c; }
    .flap-medium { background:#2d1f07; color:#fcd34d; border:1px solid #d97706; }
    .badge-vlan  { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; background:#0f1f3a; color:#93c5fd; border:1px solid #1d4ed8; }
    .row-count { font-size:12px; color:var(--text-light); padding:8px 15px; border-top:1px solid var(--border); }

    .empty-state { text-align:center; padding:60px 20px; color:var(--text-light); }
    .empty-state i  { font-size:48px; color:var(--success); margin-bottom:16px; display:block; }
    .empty-state h2 { font-size:18px; color:var(--success); margin-bottom:8px; }

    .btn { padding:8px 14px; border-radius:8px; border:none; cursor:pointer; font-size:13px; font-weight:600; display:inline-flex; align-items:center; gap:6px; text-decoration:none; }
    .btn-secondary { background:var(--dark-light); border:1px solid var(--border); color:var(--text); }
    .btn-secondary:hover { border-color:var(--primary); color:var(--primary); }
    .btn-secondary.active { border-color:var(--warning); color:var(--warning); background:rgba(245,158,11,0.08); }
    .btn-hide-row { padding:2px 8px; font-size:11px; border-radius:4px; border:1px solid #ef4444; color:#ef4444; background:transparent; cursor:pointer; white-space:nowrap; }
    .btn-hide-row:hover { background:rgba(239,68,68,0.12); }
    .btn-goto-port { padding:2px 8px; font-size:11px; border-radius:4px; border:1px solid #3b82f6; color:#3b82f6; background:transparent; cursor:pointer; white-space:nowrap; text-decoration:none; display:inline-flex; align-items:center; gap:4px; margin-right:4px; }
    .btn-goto-port:hover { background:rgba(59,130,246,0.12); }
    /* Download password modal */
    .dl-modal { display:none; position:fixed; z-index:10000; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.7); backdrop-filter:blur(5px); justify-content:center; align-items:center; }
    .dl-modal.show { display:flex; }
    .dl-modal-content { background:var(--dark-light); padding:30px; border-radius:15px; width:90%; max-width:420px; box-shadow:0 10px 30px rgba(0,0,0,0.5); }
    .dl-modal-title { font-size:17px; font-weight:bold; color:var(--text); margin-bottom:12px; display:flex; align-items:center; gap:10px; }
    .dl-modal-body { color:var(--text-light); font-size:13px; margin-bottom:18px; line-height:1.5; }
    .dl-modal-input { width:100%; padding:9px 12px; background:var(--dark); border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:14px; box-sizing:border-box; margin-bottom:6px; }
    .dl-modal-input:focus { outline:none; border-color:#0ea5e9; }
    .dl-modal-error { font-size:12px; color:#f87171; display:none; margin-bottom:16px; }
    .dl-modal-actions { display:flex; gap:10px; justify-content:flex-end; }

    .flap-bar { height:4px; border-radius:2px; background:#2b1010; margin-top:4px; overflow:hidden; }
    .flap-fill { height:100%; border-radius:2px; background:var(--danger); }
</style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="header">
        <div class="header-icon"><i class="fas fa-exchange-alt"></i></div>
        <div>
            <h1>Up/Down Döngüsü Raporu</h1>
            <p>
                Son <strong>1 saat</strong> içinde <strong>2 veya daha fazla</strong> durum değişikliği yaşayan portlar.
                &nbsp;·&nbsp; Son yenileme: <strong><?= date('d.m.Y H:i:s') ?></strong>
            </p>
        </div>
    </div>

    <!-- Stats -->
    <div class="stats-bar">
        <div class="stat-card <?= $cnt > 0 ? 'red' : 'info' ?>">
            <div class="num"><?= $cnt ?></div>
            <div class="label">Döngü Port</div>
        </div>
        <div class="stat-card orange">
            <div class="num"><?= $totalChanges ?></div>
            <div class="label">Toplam Değişim</div>
        </div>
        <?php
        $highRisk = count(array_filter($ports, fn($p) => (int)$p['change_count'] >= 5));
        ?>
        <div class="stat-card <?= $highRisk > 0 ? 'red' : 'info' ?>">
            <div class="num"><?= $highRisk ?></div>
            <div class="label">5+ Değişim</div>
        </div>
        <div class="stat-card info">
            <div class="num"><?= count(array_unique(array_column($ports, 'switch_name'))) ?></div>
            <div class="label">Etkilenen Switch</div>
        </div>
    </div>

    <!-- Toolbar -->
    <div class="toolbar">
        <div class="search-box">
            <i class="fas fa-search"></i>
            <input type="text" id="searchInput" placeholder="Switch adı veya port ara…" oninput="filterTable()">
        </div>
        <button class="btn btn-secondary" onclick="location.reload()"><i class="fas fa-sync-alt"></i> Yenile</button>
        <button class="btn btn-secondary" id="btnShowHidden" onclick="toggleHiddenView()" disabled>
            <i class="fas fa-eye" id="btnHideIcon"></i> <span id="btnHideLabel">Gizlileri Göster (0)</span>
        </button>
        <?php if ($cnt > 0): ?>
        <button class="btn btn-secondary" onclick="openDlModal()"><i class="fas fa-file-excel"></i> Excel</button>
        <?php endif; ?>
    </div>

    <div class="section-title"><i class="fas fa-exclamation-triangle"></i> Döngü Yapan Portlar</div>

    <div class="table-wrap">
        <?php if (empty($ports)): ?>
        <div class="empty-state">
            <i class="fas fa-check-circle"></i>
            <h2>Döngü Yok!</h2>
            <p>Son 1 saat içinde tekrarlayan durum değişikliği gözlemlenmedi.</p>
        </div>
        <?php else: ?>
        <table id="flapTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Switch <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(1)">Port <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(2)">Alias <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(3)">VLAN <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(4)">Değişim Sayısı <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(5)">İlk Değişim <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(6)">Son Değişim <span class="sort-icon fas fa-sort"></span></th>
                    <th style="width:160px"></th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <?php foreach ($ports as $row):
                    $changes = (int)$row['change_count'];
                    $flapClass = $changes >= 5 ? 'flap-high' : 'flap-medium';
                    $flapPct   = $maxChanges > 0 ? round($changes / $maxChanges * 100) : 0;
                    $ts1 = !empty($row['first_change']) ? date('d.m.Y H:i:s', strtotime($row['first_change'])) : '-';
                    $ts2 = !empty($row['last_change'])  ? date('d.m.Y H:i:s', strtotime($row['last_change']))  : '-';
                    $alias = trim($row['alias'] ?? '');
                    $rowKey = htmlspecialchars('flap:' . ($row['switch_name'] ?? '') . ':' . (int)$row['port_number']);
                ?>
                <tr data-rowkey="<?= $rowKey ?>">
                    <td>
                        <?= htmlspecialchars($row['switch_name'] ?? '-') ?>
                        <?php if (!empty($row['ip_address'])): ?>
                        <br><span style="color:var(--text-light);font-size:11px"><?= htmlspecialchars($row['ip_address']) ?></span>
                        <?php endif; ?>
                    </td>
                    <td><?= (int)$row['port_number'] ?></td>
                    <td style="font-size:12px"><?= $alias !== '' ? htmlspecialchars($alias) : '<span style="color:#475569">—</span>' ?></td>
                    <td><?= $row['vlan_id'] ? '<span class="badge-vlan">' . (int)$row['vlan_id'] . '</span>' : '-' ?></td>
                    <td>
                        <span class="badge-flap <?= $flapClass ?>">
                            <i class="fas fa-bolt"></i> <?= $changes ?>x
                        </span>
                        <div class="flap-bar"><div class="flap-fill" style="width:<?= $flapPct ?>%"></div></div>
                    </td>
                    <td style="color:var(--text-light);font-size:12px"><?= $ts1 ?></td>
                    <td style="color:var(--text-light);font-size:12px"><?= $ts2 ?></td>
                    <td style="text-align:right;white-space:nowrap;padding-right:10px">
                        <button class="btn-goto-port" onclick="gotoPort(<?= htmlspecialchars(json_encode($row['switch_name']), ENT_QUOTES) ?>,<?= (int)$row['port_number'] ?>)" title="Bu porta git"><i class="fas fa-plug"></i> Porta Git</button>
                        <button class="btn-hide-row" onclick="hideRow('<?= $rowKey ?>')" title="Bu satırı gizle"><i class="fas fa-eye-slash"></i> Gizle</button>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <div class="row-count" id="rowCount">
            Toplam <strong><?= $cnt ?></strong> port gösteriliyor.
        </div>
        <?php endif; ?>
    </div>

</div>

<!-- Download password modal -->
<div id="dlPasswordModal" class="dl-modal">
    <div class="dl-modal-content">
        <div class="dl-modal-title"><i class="fas fa-lock" style="color:#0ea5e9;"></i> İndirme Onayı</div>
        <div class="dl-modal-body">Excel dosyasını indirmek için şifrenizi girin.</div>
        <input type="password" id="dlPassword" class="dl-modal-input" placeholder="Şifreniz…" autocomplete="current-password">
        <div class="dl-modal-error" id="dlPasswordError">Şifre hatalı. Lütfen tekrar deneyin.</div>
        <div class="dl-modal-actions">
            <button onclick="closeDlModal()" style="padding:9px 20px;border:1px solid var(--border);background:transparent;color:var(--text-light);border-radius:8px;cursor:pointer;font-size:14px;">
                <i class="fas fa-times"></i> İptal
            </button>
            <button id="dlConfirmBtn" onclick="confirmDownload()" style="padding:9px 20px;background:#0ea5e9;color:white;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;">
                <i class="fas fa-file-excel"></i> İndir
            </button>
        </div>
    </div>
</div>

<script>
// ── Hide / Show (server-side) ─────────────────────────────────────────────────
let hiddenRows   = new Set();
let showingHidden = false;

function loadHiddenRows() {
    fetch('../api/hidden_ports_api.php')
        .then(r => r.json())
        .then(d => {
            if (d.success) {
                hiddenRows = new Set(d.hidden.filter(k => k.startsWith('flap:')));
                updateHideBtn();
                filterTable();
            }
        })
        .catch(() => {});
}

function saveHide(key) {
    fetch('../api/hidden_ports_api.php', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'hide',row_key:key}) }).catch(()=>{});
}
function saveShow(key) {
    fetch('../api/hidden_ports_api.php', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'show',row_key:key}) }).catch(()=>{});
}

function hideRow(key) {
    hiddenRows.add(key);
    saveHide(key);
    updateHideBtn();
    updateRowButtons();
    filterTable();
}
function showRow(key) {
    hiddenRows.delete(key);
    saveShow(key);
    if (!hiddenRows.size) showingHidden = false;
    updateHideBtn();
    updateRowButtons();
    filterTable();
}
function toggleHiddenView() {
    showingHidden = !showingHidden;
    updateHideBtn();
    updateRowButtons();
    filterTable();
}
function updateHideBtn() {
    const btn   = document.getElementById('btnShowHidden');
    const label = document.getElementById('btnHideLabel');
    const icon  = document.getElementById('btnHideIcon');
    const n     = hiddenRows.size;
    if (showingHidden) {
        label.textContent = '← Tüm Portlar';
        icon.className    = 'fas fa-list';
        btn.disabled      = false;
        btn.classList.add('active');
    } else {
        label.textContent = 'Gizlileri Göster (' + n + ')';
        icon.className    = 'fas fa-eye';
        btn.disabled      = n === 0;
        btn.classList.toggle('active', n > 0);
    }
}
function updateRowButtons() {
    document.querySelectorAll('#tableBody tr').forEach(tr => {
        const key     = tr.dataset.rowkey || '';
        const hideBtn = tr.querySelector('.btn-hide-row');
        if (!hideBtn) return;
        if (showingHidden) {
            hideBtn.innerHTML = '<i class="fas fa-eye"></i> Göster';
            hideBtn.onclick   = () => showRow(key);
            hideBtn.title     = 'Bu satırı geri göster';
        } else {
            hideBtn.innerHTML = '<i class="fas fa-eye-slash"></i> Gizle';
            hideBtn.onclick   = () => hideRow(key);
            hideBtn.title     = 'Bu satırı gizle';
        }
    });
}

// ── Filter ────────────────────────────────────────────────────────────────────
function filterTable() {
    const q = document.getElementById('searchInput').value.toLowerCase();
    const rows = document.querySelectorAll('#tableBody tr');
    let visible = 0;
    rows.forEach(tr => {
        const rowKey = tr.dataset.rowkey || '';
        let show;
        if (showingHidden) {
            show = hiddenRows.has(rowKey);
        } else {
            show = (!q || tr.textContent.toLowerCase().includes(q)) && !hiddenRows.has(rowKey);
        }
        tr.style.display = show ? '' : 'none';
        if (show) visible++;
    });
    const rc = document.getElementById('rowCount');
    if (rc) rc.innerHTML = showingHidden
        ? `<strong>${visible}</strong> gizli kayıt listeleniyor.`
        : `<strong>${visible}</strong> port gösteriliyor.`;
}

document.addEventListener('DOMContentLoaded', function() {
    loadHiddenRows();
    updateHideBtn();
    updateRowButtons();
});

// ── Sort ──────────────────────────────────────────────────────────────────────
let sortState = { col: -1, asc: true };
function sortTable(col) {
    const tbody = document.getElementById('tableBody');
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const asc  = (sortState.col === col) ? !sortState.asc : true;
    sortState  = { col, asc };
    rows.sort((a, b) => {
        const va = a.querySelectorAll('td')[col]?.textContent.trim() ?? '';
        const vb = b.querySelectorAll('td')[col]?.textContent.trim() ?? '';
        const na = parseFloat(va), nb = parseFloat(vb);
        const cmp = (!isNaN(na) && !isNaN(nb)) ? na - nb : va.localeCompare(vb, 'tr');
        return asc ? cmp : -cmp;
    });
    rows.forEach(r => tbody.appendChild(r));
    document.querySelectorAll('thead th').forEach((th, i) => {
        th.classList.toggle('sorted', i === col);
        const icon = th.querySelector('.sort-icon');
        if (icon) icon.className = 'sort-icon fas ' + (i !== col ? 'fa-sort' : asc ? 'fa-sort-up' : 'fa-sort-down');
    });
}

// ── Porta Git ─────────────────────────────────────────────────────────────────
function gotoPort(switchName, portNumber) {
    if (window.parent && window.parent !== window && typeof window.parent.gotoPortInline === 'function') {
        window.parent.gotoPortInline(switchName, portNumber);
    } else {
        window.open('../index.php?switch=' + encodeURIComponent(switchName) + '&port=' + portNumber, '_blank');
    }
}

// ── Download password modal ───────────────────────────────────────────────────
function openDlModal() {
    document.getElementById('dlPassword').value = '';
    document.getElementById('dlPasswordError').style.display = 'none';
    document.getElementById('dlPasswordModal').classList.add('show');
    setTimeout(() => document.getElementById('dlPassword').focus(), 50);
}
function closeDlModal() {
    document.getElementById('dlPasswordModal').classList.remove('show');
    document.getElementById('dlPassword').value = '';
    document.getElementById('dlPasswordError').style.display = 'none';
}
document.getElementById('dlPasswordModal').addEventListener('click', function(e) { if (e.target === this) closeDlModal(); });
document.getElementById('dlPassword').addEventListener('keydown', function(e) { if (e.key === 'Enter') confirmDownload(); });

async function confirmDownload() {
    const password = document.getElementById('dlPassword').value;
    const errEl    = document.getElementById('dlPasswordError');
    const btn      = document.getElementById('dlConfirmBtn');
    if (!password) { errEl.textContent = 'Şifre boş olamaz.'; errEl.style.display = 'block'; document.getElementById('dlPassword').focus(); return; }
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Doğrulanıyor…';
    errEl.style.display = 'none';
    try {
        const res  = await fetch('../api/export_excel.php?type=flapping', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password}) });
        const data = await res.json();
        if (!data.success) {
            errEl.textContent = data.error || 'Şifre hatalı.';
            errEl.style.display = 'block';
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-file-excel"></i> İndir';
            document.getElementById('dlPassword').focus();
            document.getElementById('dlPassword').select();
            return;
        }
        closeDlModal();
        window.location.href = '../api/export_excel.php?type=flapping';
    } catch(e) {
        errEl.textContent = 'Sunucu hatası. Lütfen tekrar deneyin.';
        errEl.style.display = 'block';
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-file-excel"></i> İndir';
    }
}
</script>
</body>
</html>
