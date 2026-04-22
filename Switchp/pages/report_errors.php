<?php
/**
 * report_errors.php — Hata / Drop Raporu
 * in_errors, out_errors, in_discards, out_discards sıfırdan büyük olan portları listeler.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();
session_write_close();

header('Cache-Control: no-cache, no-store, must-revalidate');

// ── Hata / Drop olan portlar ──────────────────────────────────────────────────
$sql = "
    SELECT
        psd.device_id,
        psd.port_number,
        psd.port_name,
        psd.port_alias,
        psd.vlan_id,
        psd.oper_status,
        COALESCE(psd.in_errors,   0) AS in_errors,
        COALESCE(psd.out_errors,  0) AS out_errors,
        COALESCE(psd.in_discards, 0) AS in_discards,
        COALESCE(psd.out_discards,0) AS out_discards,
        COALESCE(psd.in_errors,0) + COALESCE(psd.out_errors,0)
            + COALESCE(psd.in_discards,0) + COALESCE(psd.out_discards,0) AS total_issues,
        sd.name        AS switch_name,
        sd.ip_address,
        mdr.device_name AS conn_device,
        psd.poll_timestamp
    FROM port_status_data psd
    JOIN snmp_devices sd ON sd.id = psd.device_id
    LEFT JOIN mac_device_registry mdr ON mdr.mac_address = psd.mac_address
    WHERE (
        COALESCE(psd.in_errors,   0) > 0 OR
        COALESCE(psd.out_errors,  0) > 0 OR
        COALESCE(psd.in_discards, 0) > 0 OR
        COALESCE(psd.out_discards,0) > 0
    )
    ORDER BY
        (COALESCE(psd.in_errors,0) + COALESCE(psd.out_errors,0)
         + COALESCE(psd.in_discards,0) + COALESCE(psd.out_discards,0)) DESC,
        sd.name,
        psd.port_number
";
$result = $conn->query($sql);
$ports  = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
$cnt    = count($ports);

// Özet sayılar
$totalInErr  = array_sum(array_column($ports, 'in_errors'));
$totalOutErr = array_sum(array_column($ports, 'out_errors'));
$totalInDis  = array_sum(array_column($ports, 'in_discards'));
$totalOutDis = array_sum(array_column($ports, 'out_discards'));

// Switch filtre listesi
$switchList = array_unique(array_column($ports, 'switch_name'));
sort($switchList);
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hata / Drop Raporu</title>
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
    .container { max-width:1400px; margin:0 auto; }

    .header { background:var(--dark-light); padding:20px 24px; border-radius:12px; border:1px solid var(--border); margin-bottom:20px; display:flex; align-items:center; gap:16px; }
    .header-icon { font-size:32px; color:var(--warning); }
    .header h1  { color:var(--warning); font-size:20px; margin-bottom:4px; }
    .header p   { color:var(--text-light); font-size:12px; line-height:1.5; }

    .section-title { font-size:12px; text-transform:uppercase; letter-spacing:1px; color:var(--text-light); margin-bottom:12px; display:flex; align-items:center; gap:8px; }
    .section-title i { color:var(--warning); }

    .stats-bar { display:grid; grid-template-columns:repeat(auto-fit,minmax(155px,1fr)); gap:14px; margin-bottom:20px; }
    .stat-card { background:var(--dark-light); padding:16px; border-radius:10px; border:1px solid var(--border); text-align:center; }
    .stat-card .num   { font-size:26px; font-weight:700; margin-bottom:4px; }
    .stat-card .label { font-size:11px; color:var(--text-light); text-transform:uppercase; letter-spacing:0.8px; }
    .stat-card.warn   .num { color:var(--warning); }
    .stat-card.red    .num { color:var(--danger); }
    .stat-card.info   .num { color:var(--primary); }

    .toolbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
    .search-box { position:relative; flex:1; min-width:200px; }
    .search-box i { position:absolute; left:10px; top:50%; transform:translateY(-50%); color:var(--text-light); font-size:12px; }
    .search-box input { width:100%; padding:8px 10px 8px 32px; background:var(--dark-light); border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:13px; outline:none; }
    .search-box input:focus { border-color:var(--primary); }
    select.filter-select { padding:8px 10px; background:var(--dark-light); border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:13px; outline:none; cursor:pointer; }
    select.filter-select:focus { border-color:var(--primary); }

    .table-wrap { background:var(--dark-light); border-radius:12px; border:1px solid var(--border); overflow:hidden; }
    table { width:100%; border-collapse:collapse; }
    thead th { background:#2d1f07; padding:11px 14px; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:var(--text-light); text-align:left; border-bottom:1px solid var(--border); white-space:nowrap; cursor:pointer; user-select:none; }
    thead th:hover { color:var(--warning); }
    thead th .sort-icon { margin-left:4px; opacity:0.4; font-size:10px; }
    thead th.sorted .sort-icon { opacity:1; color:var(--warning); }
    tbody tr { border-bottom:1px solid #1e2a3a; transition:background 0.15s; }
    tbody tr:last-child { border-bottom:none; }
    tbody tr:hover { background:#211a0a; }
    tbody td { padding:10px 14px; font-size:13px; }

    .val-err  { color:var(--danger);  font-weight:700; }
    .val-warn { color:var(--warning); font-weight:700; }
    .val-zero { color:#475569; }
    .badge-vlan { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; background:#0f1f3a; color:#93c5fd; border:1px solid #1d4ed8; }
    .badge-up   { background:#0d2b1a; color:#4ade80; border:1px solid #16a34a; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
    .badge-down { background:#2b0d0d; color:#f87171; border:1px solid #b91c1c; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
    .row-count { font-size:12px; color:var(--text-light); padding:8px 14px; border-top:1px solid var(--border); }

    .empty-state { text-align:center; padding:60px 20px; color:var(--text-light); }
    .empty-state i  { font-size:48px; color:var(--success); margin-bottom:16px; display:block; }
    .empty-state h2 { font-size:18px; color:var(--success); margin-bottom:8px; }

    .btn { padding:8px 14px; border-radius:8px; border:none; cursor:pointer; font-size:13px; font-weight:600; display:inline-flex; align-items:center; gap:6px; }
    .btn-secondary { background:var(--dark-light); border:1px solid var(--border); color:var(--text); }
    .btn-secondary:hover { border-color:var(--primary); color:var(--primary); }

    /* Total issues mini badge */
    .total-issues { display:inline-block; padding:3px 9px; border-radius:10px; font-size:12px; font-weight:700; background:#2d1f07; color:#fcd34d; border:1px solid #d97706; }
</style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="header">
        <div class="header-icon"><i class="fas fa-bug"></i></div>
        <div>
            <h1>Hata / Drop Raporu</h1>
            <p>
                Gelen/Giden Hata veya Drop (in_discards, out_discards) değeri sıfırdan büyük olan tüm portlar.
                &nbsp;·&nbsp; Son yenileme: <strong><?= date('d.m.Y H:i:s') ?></strong>
            </p>
        </div>
    </div>

    <!-- Stats -->
    <div class="stats-bar">
        <div class="stat-card <?= $cnt > 0 ? 'warn' : 'info' ?>">
            <div class="num"><?= $cnt ?></div>
            <div class="label">Hatalı Port</div>
        </div>
        <div class="stat-card red">
            <div class="num"><?= number_format($totalInErr + $totalOutErr) ?></div>
            <div class="label">Toplam Hata</div>
        </div>
        <div class="stat-card warn">
            <div class="num"><?= number_format($totalInDis + $totalOutDis) ?></div>
            <div class="label">Toplam Drop</div>
        </div>
        <div class="stat-card info">
            <div class="num"><?= count($switchList) ?></div>
            <div class="label">Etkilenen Switch</div>
        </div>
        <div class="stat-card red">
            <div class="num"><?= number_format($totalInErr) ?></div>
            <div class="label">Gelen Hata</div>
        </div>
        <div class="stat-card red">
            <div class="num"><?= number_format($totalOutErr) ?></div>
            <div class="label">Giden Hata</div>
        </div>
    </div>

    <!-- Toolbar -->
    <div class="toolbar">
        <div class="search-box">
            <i class="fas fa-search"></i>
            <input type="text" id="searchInput" placeholder="Switch, port veya cihaz ara…" oninput="filterTable()">
        </div>
        <select class="filter-select" id="switchFilter" onchange="filterTable()">
            <option value="">Tüm Switch'ler</option>
            <?php foreach ($switchList as $sw): ?>
            <option value="<?= htmlspecialchars($sw) ?>"><?= htmlspecialchars($sw) ?></option>
            <?php endforeach; ?>
        </select>
        <select class="filter-select" id="typeFilter" onchange="filterTable()">
            <option value="">Tüm Hata Türleri</option>
            <option value="in_errors">Gelen Hata</option>
            <option value="out_errors">Giden Hata</option>
            <option value="in_discards">Drop (Gelen)</option>
            <option value="out_discards">Drop (Giden)</option>
        </select>
        <button class="btn btn-secondary" onclick="location.reload()"><i class="fas fa-sync-alt"></i> Yenile</button>
        <?php if ($cnt > 0): ?>
        <button class="btn btn-secondary" onclick="exportXLSX()"><i class="fas fa-file-excel"></i> Excel</button>
        <?php endif; ?>
    </div>

    <div class="section-title"><i class="fas fa-exclamation-circle"></i> Hata ve Drop Bulunan Portlar</div>

    <div class="table-wrap">
        <?php if (empty($ports)): ?>
        <div class="empty-state">
            <i class="fas fa-check-circle"></i>
            <h2>Hata Yok!</h2>
            <p>Tüm portlarda hata ve drop değerleri sıfır.</p>
        </div>
        <?php else: ?>
        <table id="errTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Switch <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(1)">Port <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(2)">Cihaz / Alias <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(3)">VLAN <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(4)">Durum <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(5)" title="Gelen Hata">↓ Hata <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(6)" title="Giden Hata">↑ Hata <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(7)" title="Drop (Gelen)">↓ Drop <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(8)" title="Drop (Giden)">↑ Drop <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(9)">Toplam <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(10)">Son Poll <span class="sort-icon fas fa-sort"></span></th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <?php foreach ($ports as $row):
                    $inErr  = (int)$row['in_errors'];
                    $outErr = (int)$row['out_errors'];
                    $inDis  = (int)$row['in_discards'];
                    $outDis = (int)$row['out_discards'];
                    $total  = $inErr + $outErr + $inDis + $outDis;
                    $alias  = trim($row['port_alias'] ?? '');
                    $connDev = trim($row['conn_device'] ?? '');
                    $label  = $connDev !== '' ? $connDev : ($alias !== '' ? $alias : '—');
                    $ts = !empty($row['poll_timestamp'])
                        ? date('d.m.Y H:i', strtotime($row['poll_timestamp'])) : '-';
                    $statusClass = ($row['oper_status'] === 'up') ? 'badge-up' : 'badge-down';
                    $statusText  = strtoupper($row['oper_status'] ?? 'UNKNOWN');

                    // data attributes for type filter
                    $typeAttr = '';
                    if ($inErr  > 0) $typeAttr .= ' in_errors';
                    if ($outErr > 0) $typeAttr .= ' out_errors';
                    if ($inDis  > 0) $typeAttr .= ' in_discards';
                    if ($outDis > 0) $typeAttr .= ' out_discards';
                ?>
                <tr data-switch="<?= htmlspecialchars($row['switch_name'] ?? '') ?>"
                    data-types="<?= trim($typeAttr) ?>">
                    <td>
                        <?= htmlspecialchars($row['switch_name'] ?? '-') ?>
                        <?php if (!empty($row['ip_address'])): ?>
                        <br><span style="color:var(--text-light);font-size:11px"><?= htmlspecialchars($row['ip_address']) ?></span>
                        <?php endif; ?>
                    </td>
                    <td><?= (int)$row['port_number'] ?></td>
                    <td style="font-size:12px">
                        <?= htmlspecialchars($label) ?>
                        <?php if ($connDev !== '' && $alias !== ''): ?>
                        <br><span style="color:var(--text-light)"><?= htmlspecialchars($alias) ?></span>
                        <?php endif; ?>
                    </td>
                    <td><?= $row['vlan_id'] ? '<span class="badge-vlan">' . (int)$row['vlan_id'] . '</span>' : '-' ?></td>
                    <td><span class="<?= $statusClass ?>"><?= $statusText ?></span></td>
                    <td><span class="<?= $inErr  > 0 ? 'val-err'  : 'val-zero' ?>"><?= number_format($inErr)  ?></span></td>
                    <td><span class="<?= $outErr > 0 ? 'val-err'  : 'val-zero' ?>"><?= number_format($outErr) ?></span></td>
                    <td><span class="<?= $inDis  > 0 ? 'val-warn' : 'val-zero' ?>"><?= number_format($inDis)  ?></span></td>
                    <td><span class="<?= $outDis > 0 ? 'val-warn' : 'val-zero' ?>"><?= number_format($outDis) ?></span></td>
                    <td><span class="total-issues"><?= number_format($total) ?></span></td>
                    <td style="color:var(--text-light);font-size:11px"><?= $ts ?></td>
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
    const q       = document.getElementById('searchInput').value.toLowerCase();
    const swF     = document.getElementById('switchFilter').value;
    const typeF   = document.getElementById('typeFilter').value;
    const rows    = document.querySelectorAll('#tableBody tr');
    let visible = 0;
    rows.forEach(tr => {
        const matchQ  = !q     || tr.textContent.toLowerCase().includes(q);
        const matchSw = !swF   || tr.dataset.switch === swF;
        const matchT  = !typeF || (tr.dataset.types || '').includes(typeF);
        const show = matchQ && matchSw && matchT;
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
        const va = a.querySelectorAll('td')[col]?.textContent.trim().replace(/,/g, '') ?? '';
        const vb = b.querySelectorAll('td')[col]?.textContent.trim().replace(/,/g, '') ?? '';
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
    const headers = ['Switch', 'Port', 'Cihaz/Alias', 'VLAN', 'Durum', 'Gelen Hata', 'Giden Hata', 'Drop (Gelen)', 'Drop (Giden)', 'Toplam', 'Son Poll'];
    const rows = Array.from(document.querySelectorAll('#tableBody tr'))
        .filter(r => r.style.display !== 'none')
        .map(r => Array.from(r.querySelectorAll('td')).map(td => td.textContent.trim()));
    const ws = XLSX.utils.aoa_to_sheet([headers, ...rows]);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Hata-Drop');
    XLSX.writeFile(wb, 'hata_drop_raporu_' + new Date().toISOString().slice(0,10) + '.xlsx');
}
</script>
</body>
</html>
