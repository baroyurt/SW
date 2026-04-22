<?php
/**
 * report_vlan_dist.php — VLAN Dağılımı Raporu
 * VLAN bazında kaç port (up / down) olduğunu listeler.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();
session_write_close();

header('Cache-Control: no-cache, no-store, must-revalidate');

// ── VLAN bazında port sayıları ────────────────────────────────────────────────
$sql = "
    SELECT
        psd.vlan_id,
        COUNT(*)                                                    AS port_count,
        SUM(CASE WHEN psd.oper_status = 'up'   THEN 1 ELSE 0 END) AS up_count,
        SUM(CASE WHEN psd.oper_status = 'down' THEN 1 ELSE 0 END) AS down_count
    FROM port_status_data psd
    WHERE psd.vlan_id IS NOT NULL
      AND psd.vlan_id > 0
    GROUP BY psd.vlan_id
    ORDER BY COUNT(*) DESC
";
$result = $conn->query($sql);
$rows   = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];

// Toplam port adedi
$totalPorts = array_sum(array_column($rows, 'port_count'));
$maxCount   = $rows ? max(array_column($rows, 'port_count')) : 1;

// ── Switch bazında VLAN dağılımı (top-20) ────────────────────────────────────
$swSql = "
    SELECT
        sd.name    AS switch_name,
        psd.vlan_id,
        COUNT(*)   AS port_count
    FROM port_status_data psd
    JOIN snmp_devices sd ON sd.id = psd.device_id
    WHERE psd.vlan_id IS NOT NULL AND psd.vlan_id > 0
    GROUP BY sd.name, psd.vlan_id
    ORDER BY sd.name, psd.vlan_id
";
$swRes    = $conn->query($swSql);
$swRows   = $swRes ? $swRes->fetch_all(MYSQLI_ASSOC) : [];

// Re-index by switch
$bySwitch = [];
foreach ($swRows as $r) {
    $bySwitch[$r['switch_name']][$r['vlan_id']] = (int)$r['port_count'];
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VLAN Dağılımı</title>
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
    .container { max-width:1200px; margin:0 auto; }

    .header { background:var(--dark-light); padding:20px 24px; border-radius:12px; border:1px solid var(--border); margin-bottom:20px; display:flex; align-items:center; gap:16px; }
    .header-icon { font-size:32px; color:#8b5cf6; }
    .header h1  { color:#8b5cf6; font-size:20px; margin-bottom:4px; }
    .header p   { color:var(--text-light); font-size:12px; }

    .section-title { font-size:12px; text-transform:uppercase; letter-spacing:1px; color:var(--text-light); margin-bottom:12px; display:flex; align-items:center; gap:8px; }
    .section-title i { color:var(--primary); }

    .stats-bar { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:20px; }
    .stat-card { background:var(--dark-light); padding:18px; border-radius:10px; border:1px solid var(--border); text-align:center; }
    .stat-card .num   { font-size:28px; font-weight:700; margin-bottom:4px; }
    .stat-card .label { font-size:11px; color:var(--text-light); text-transform:uppercase; letter-spacing:1px; }
    .stat-card.purple .num { color:#a78bfa; }
    .stat-card.green  .num { color:var(--success); }
    .stat-card.red    .num { color:var(--danger); }

    .toolbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
    .search-box { position:relative; flex:1; min-width:200px; }
    .search-box i { position:absolute; left:10px; top:50%; transform:translateY(-50%); color:var(--text-light); font-size:12px; }
    .search-box input { width:100%; padding:8px 10px 8px 32px; background:var(--dark-light); border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:13px; outline:none; }
    .search-box input:focus { border-color:var(--primary); }

    /* VLAN row */
    .vlan-list { background:var(--dark-light); border-radius:12px; border:1px solid var(--border); overflow:hidden; }
    .vlan-row { display:grid; grid-template-columns:80px 1fr 120px 90px 90px; align-items:center; gap:12px; padding:12px 18px; border-bottom:1px solid #1e2a3a; }
    .vlan-row:last-child { border-bottom:none; }
    .vlan-row:hover { background:#1a2a40; }
    .vlan-row.head { background:#0f1f3a; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:var(--text-light); font-weight:600; }
    .badge-vlan { display:inline-block; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:700; background:#0f1f3a; color:#93c5fd; border:1px solid #1d4ed8; }
    .progress-bar { background:#1e2a3a; border-radius:4px; height:10px; overflow:hidden; }
    .progress-fill { height:100%; border-radius:4px; background:linear-gradient(90deg,#3b82f6,#8b5cf6); transition:width .3s; }
    .cnt { font-size:14px; font-weight:700; }
    .cnt-up   { color:var(--success); }
    .cnt-down { color:var(--danger); }
    .row-count { font-size:12px; color:var(--text-light); padding:8px 18px; border-top:1px solid var(--border); }

    /* Switch breakdown table */
    .table-wrap { background:var(--dark-light); border-radius:12px; border:1px solid var(--border); overflow:auto; margin-top:24px; }
    table { width:100%; border-collapse:collapse; min-width:600px; }
    thead th { background:#0f1f3a; padding:10px 14px; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:var(--text-light); text-align:left; border-bottom:1px solid var(--border); white-space:nowrap; }
    tbody tr { border-bottom:1px solid #1e2a3a; }
    tbody tr:last-child { border-bottom:none; }
    tbody tr:hover { background:#1a2a40; }
    tbody td { padding:10px 14px; font-size:13px; }
    .btn { padding:8px 14px; border-radius:8px; border:none; cursor:pointer; font-size:13px; font-weight:600; display:inline-flex; align-items:center; gap:6px; }
    .btn-secondary { background:var(--dark-light); border:1px solid var(--border); color:var(--text); }
    .btn-secondary:hover { border-color:var(--primary); color:var(--primary); }
</style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="header">
        <div class="header-icon"><i class="fas fa-layer-group"></i></div>
        <div>
            <h1>VLAN Dağılımı Raporu</h1>
            <p>Her VLAN'daki UP / DOWN port sayıları &nbsp;·&nbsp; Son yenileme: <strong><?= date('d.m.Y H:i:s') ?></strong></p>
        </div>
    </div>

    <!-- Stats -->
    <div class="stats-bar">
        <div class="stat-card purple">
            <div class="num"><?= count($rows) ?></div>
            <div class="label">Farklı VLAN</div>
        </div>
        <div class="stat-card purple">
            <div class="num"><?= $totalPorts ?></div>
            <div class="label">Toplam Port</div>
        </div>
        <div class="stat-card green">
            <div class="num"><?= array_sum(array_column($rows, 'up_count')) ?></div>
            <div class="label">UP Port</div>
        </div>
        <div class="stat-card red">
            <div class="num"><?= array_sum(array_column($rows, 'down_count')) ?></div>
            <div class="label">DOWN Port</div>
        </div>
    </div>

    <!-- Toolbar -->
    <div class="toolbar">
        <div class="search-box">
            <i class="fas fa-search"></i>
            <input type="text" id="searchInput" placeholder="VLAN ID ara…" oninput="filterRows()">
        </div>
        <button class="btn btn-secondary" onclick="location.reload()"><i class="fas fa-sync-alt"></i> Yenile</button>
    </div>

    <div class="section-title"><i class="fas fa-chart-bar"></i> VLAN Bazında Port Sayıları</div>

    <!-- VLAN list -->
    <div class="vlan-list">
        <div class="vlan-row head">
            <div>VLAN ID</div>
            <div>Dağılım</div>
            <div>Toplam</div>
            <div>UP</div>
            <div>DOWN</div>
        </div>
        <?php foreach ($rows as $r):
            $vlanId   = (int)$r['vlan_id'];
            $total    = (int)$r['port_count'];
            $up       = (int)$r['up_count'];
            $down     = (int)$r['down_count'];
            $pct      = $maxCount > 0 ? round($total / $maxCount * 100) : 0;
        ?>
        <div class="vlan-row" data-vlan="<?= $vlanId ?>">
            <div><span class="badge-vlan"><?= $vlanId ?></span></div>
            <div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width:<?= $pct ?>%"></div>
                </div>
            </div>
            <div class="cnt" style="color:var(--text)"><?= $total ?></div>
            <div class="cnt cnt-up"><?= $up ?></div>
            <div class="cnt cnt-down"><?= $down ?></div>
        </div>
        <?php endforeach; ?>
    </div>
    <div class="row-count" id="rowCount">Toplam <strong><?= count($rows) ?></strong> VLAN gösteriliyor.</div>

    <!-- Switch breakdown -->
    <?php if (!empty($bySwitch)): ?>
    <hr style="border:none;border-top:1px solid var(--border);margin:28px 0">
    <div class="section-title"><i class="fas fa-server"></i> Switch × VLAN Dökümü</div>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Switch Adı</th>
                    <?php
                    $allVlans = array_unique(array_column($swRows, 'vlan_id'));
                    sort($allVlans);
                    foreach ($allVlans as $v): ?>
                        <th>VLAN <?= $v ?></th>
                    <?php endforeach; ?>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($bySwitch as $swName => $vlanCounts): ?>
                <tr>
                    <td><?= htmlspecialchars($swName) ?></td>
                    <?php foreach ($allVlans as $v): ?>
                    <td><?= isset($vlanCounts[$v]) ? '<strong>' . $vlanCounts[$v] . '</strong>' : '<span style="color:#475569">—</span>' ?></td>
                    <?php endforeach; ?>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

</div>

<script>
function filterRows() {
    const q    = document.getElementById('searchInput').value.trim();
    const rows = document.querySelectorAll('.vlan-row:not(.head)');
    let visible = 0;
    rows.forEach(r => {
        const match = !q || r.dataset.vlan.includes(q);
        r.style.display = match ? '' : 'none';
        if (match) visible++;
    });
    document.getElementById('rowCount').innerHTML =
        `<strong>${visible}</strong> VLAN gösteriliyor.`;
}
</script>
</body>
</html>
