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
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
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
        <?php if ($cnt > 0): ?>
        <button class="btn btn-secondary" onclick="exportXLSX()"><i class="fas fa-file-excel"></i> Excel</button>
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
                ?>
                <tr>
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

<script>
function filterTable() {
    const q = document.getElementById('searchInput').value.toLowerCase();
    const rows = document.querySelectorAll('#tableBody tr');
    let visible = 0;
    rows.forEach(tr => {
        const show = !q || tr.textContent.toLowerCase().includes(q);
        tr.style.display = show ? '' : 'none';
        if (show) visible++;
    });
    const rc = document.getElementById('rowCount');
    if (rc) rc.innerHTML = `<strong>${visible}</strong> port gösteriliyor.`;
}

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

function exportXLSX() {
    const headers = ['Switch', 'Port', 'Alias', 'VLAN', 'Değişim Sayısı', 'İlk Değişim', 'Son Değişim'];
    const rows = Array.from(document.querySelectorAll('#tableBody tr'))
        .filter(r => r.style.display !== 'none')
        .map(r => Array.from(r.querySelectorAll('td')).map(td => td.textContent.trim()));
    const ws = XLSX.utils.aoa_to_sheet([headers, ...rows]);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Döngü Portlar');
    XLSX.writeFile(wb, 'updown_dongu_' + new Date().toISOString().slice(0,10) + '.xlsx');
}
</script>
</body>
</html>
