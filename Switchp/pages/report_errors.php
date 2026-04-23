<?php
/**
 * report_errors.php — Hata / Drop Analizi
 * in_errors, out_errors, out_discards (= CLI Total output drops) sıfırdan büyük olan portları listeler.
 * Fiziksel katman (kablo/SFP/port) sağlık analizi ve trafik bilgisi dahil.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();
session_write_close();

header('Cache-Control: no-cache, no-store, must-revalidate');

// ── Byte formatter ────────────────────────────────────────────────────────────
function formatBytes(int $bytes): string {
    if ($bytes <= 0)           return '0 B';
    if ($bytes < 1024)         return $bytes . ' B';
    if ($bytes < 1048576)      return round($bytes / 1024, 1) . ' KB';
    if ($bytes < 1073741824)   return round($bytes / 1048576, 1) . ' MB';
    if ($bytes < 1099511627776) return round($bytes / 1073741824, 1) . ' GB';
    return round($bytes / 1099511627776, 2) . ' TB';
}

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
        COALESCE(psd.out_discards,0) AS out_discards,
        COALESCE(psd.in_discards, 0) AS in_discards,
        COALESCE(psd.in_octets,   0) AS in_octets,
        COALESCE(psd.out_octets,  0) AS out_octets,
        COALESCE(psd.in_errors,0) + COALESCE(psd.out_errors,0)
            + COALESCE(psd.out_discards,0) AS total_issues,
        sd.name        AS switch_name,
        sd.ip_address,
        sd.model       AS sw_model,
        mdr.device_name AS conn_device,
        psd.poll_timestamp
    FROM port_status_data psd
    JOIN snmp_devices sd ON sd.id = psd.device_id
    LEFT JOIN mac_device_registry mdr ON mdr.mac_address = psd.mac_address
    WHERE (
        COALESCE(psd.in_errors,   0) > 0 OR
        COALESCE(psd.out_errors,  0) > 0 OR
        COALESCE(psd.out_discards,0) > 0
    )
    ORDER BY
        (COALESCE(psd.in_errors,0) + COALESCE(psd.out_errors,0)
         + COALESCE(psd.out_discards,0)) DESC,
        sd.name,
        psd.port_number
";
$result = $conn->query($sql);
$ports  = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
$cnt    = count($ports);

// Özet sayılar
$totalInErr  = array_sum(array_column($ports, 'in_errors'));
$totalOutErr = array_sum(array_column($ports, 'out_errors'));
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
<title>Hata / Drop Analizi</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
<style>
    html { zoom: 0.95; overflow-x:hidden; }
    body { overflow-x:hidden; }

    /* Scrollbar — Dashboard ile aynı mavi stil */
    ::-webkit-scrollbar { width:10px; height:10px; }
    ::-webkit-scrollbar-track { background:var(--dark,#0f172a); }
    ::-webkit-scrollbar-thumb { background:#3b82f6; border-radius:5px; }
    ::-webkit-scrollbar-thumb:hover { background:#2563eb; }
    * { scrollbar-width:thin; scrollbar-color:#3b82f6 #0f172a; }

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
    body { font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:var(--dark); color:var(--text); padding:20px; overflow-x:hidden; }
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
    table { width:100%; border-collapse:collapse; table-layout:fixed; }
    thead th { background:#2d1f07; padding:9px 8px; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:var(--text-light); text-align:left; border-bottom:1px solid var(--border); white-space:nowrap; cursor:pointer; user-select:none; overflow:hidden; text-overflow:ellipsis; }
    thead th:hover { color:var(--warning); }
    thead th .sort-icon { margin-left:4px; opacity:0.4; font-size:10px; }
    thead th.sorted .sort-icon { opacity:1; color:var(--warning); }
    tbody tr { border-bottom:1px solid #1e2a3a; transition:background 0.15s; }
    tbody tr:last-child { border-bottom:none; }
    tbody tr:hover { background:#211a0a; }
    tbody td { padding:8px 8px; font-size:12px; overflow:hidden; text-overflow:ellipsis; }

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
    .btn-secondary.active { border-color:var(--warning); color:var(--warning); background:rgba(245,158,11,0.08); }
    .btn-hide-row { padding:2px 8px; font-size:11px; border-radius:4px; border:1px solid #ef4444; color:#ef4444; background:transparent; cursor:pointer; white-space:nowrap; }
    .btn-hide-row:hover { background:rgba(239,68,68,0.12); }
    .btn-goto-port { padding:3px 8px; font-size:11px; border-radius:4px; border:1px solid #3b82f6; color:#3b82f6; background:transparent; cursor:pointer; white-space:nowrap; text-decoration:none; display:inline-flex; align-items:center; gap:4px; }
    .btn-goto-port:hover { background:rgba(59,130,246,0.12); }
    .action-cell { display:flex; flex-direction:column; align-items:flex-end; gap:4px; }
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

    /* Total issues mini badge */
    .total-issues { display:inline-block; padding:3px 9px; border-radius:10px; font-size:12px; font-weight:700; background:#2d1f07; color:#fcd34d; border:1px solid #d97706; }

    /* Physical layer badge */
    .phys-ok   { display:inline-flex; align-items:center; gap:4px; padding:3px 8px; border-radius:10px; font-size:11px; font-weight:700; background:#0d2b1a; color:#4ade80; border:1px solid #16a34a; white-space:nowrap; }
    .phys-warn { display:inline-flex; align-items:center; gap:4px; padding:3px 8px; border-radius:10px; font-size:11px; font-weight:700; background:#2b0d0d; color:#f87171; border:1px solid #b91c1c; white-space:nowrap; }

    /* Traffic display */
    .trafik-cell { font-size:11px; line-height:1.7; }
    .t-in  { color:#38bdf8; }
    .t-out { color:#a78bfa; }

    /* Hover-tooltip wrapper */
    .tooltip-wrap { position:relative; display:inline-block; cursor:help; }
    .tooltip-wrap .tt-box {
        display:none; position:fixed; z-index:99999;
        min-width:280px; background:#0f172a; border:1px solid #334155; border-radius:10px;
        padding:12px 14px; box-shadow:0 8px 24px rgba(0,0,0,0.6); text-align:left; pointer-events:none;
    }
    .tooltip-wrap:hover .tt-box { display:block; }
    .tt-box h4  { font-size:12px; color:#f59e0b; margin-bottom:8px; display:flex; align-items:center; gap:6px; }
    .tt-box .tt-row { font-size:11px; color:#cbd5e1; line-height:1.8; }
    .tt-box .tt-phys-ok   { color:#4ade80; font-weight:700; }
    .tt-box .tt-phys-warn { color:#f87171; font-weight:700; }
    .tt-box .tt-sep { border:none; border-top:1px solid #334155; margin:8px 0; }
    .tt-box .tt-cumul { font-size:10px; color:#64748b; font-style:italic; }
</style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="header">
        <div class="header-icon"><i class="fas fa-bug"></i></div>
        <div>
            <h1>Hata / Drop Analizi</h1>
            <p>
                Gelen/Giden Hata veya Output Drop değeri sıfırdan büyük portlar · Fiziksel katman sağlık analizi dahil.
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
            <div class="num"><?= number_format($totalOutDis) ?></div>
            <div class="label">Output Drop</div>
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
            <option value="out_discards">Output Drop</option>
        </select>
        <button class="btn btn-secondary" onclick="location.reload()"><i class="fas fa-sync-alt"></i> Yenile</button>
        <button class="btn btn-secondary" id="btnShowHidden" onclick="toggleHiddenView()" disabled>
            <i class="fas fa-eye" id="btnHideIcon"></i> <span id="btnHideLabel">Gizlileri Göster (0)</span>
        </button>
        <?php if ($cnt > 0): ?>
        <button class="btn btn-secondary" onclick="openDlModal()"><i class="fas fa-file-excel"></i> Excel</button>
        <?php endif; ?>
    </div>

    <div class="section-title"><i class="fas fa-exclamation-circle"></i> Hata ve Drop Bulunan Portlar — Analiz</div>

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
                    <th onclick="sortTable(0)" style="width:12%">Switch <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(1)" style="width:5%">Port <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(2)" style="width:10%">Cihaz / Alias <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(3)" style="width:5%">VLAN <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(4)" style="width:6%">Durum <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(5)" style="width:6%" title="Gelen Hata">↓ Hata <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(6)" style="width:6%" title="Giden Hata">↑ Hata <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(7)" style="width:6%" title="Output Drop (CLI Total output drops)">↑ Drop <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(8)" style="width:9%">Toplam <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(9)" style="width:9%" title="Trafik: Gelen / Giden bayt">Trafik ↓/↑ <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(10)" style="width:10%" title="Fiziksel katman (kablo/SFP/port) sağlık analizi">Fiziksel Katman <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(11)" style="width:8%">Son Poll <span class="sort-icon fas fa-sort"></span></th>
                    <th style="width:8%"></th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <?php foreach ($ports as $row):
                    $inErr  = (int)$row['in_errors'];
                    $outErr = (int)$row['out_errors'];
                    $outDis = (int)$row['out_discards'];
                    $inDis  = (int)$row['in_discards'];
                    $total  = $inErr + $outErr + $outDis;
                    $alias  = trim($row['port_alias'] ?? '');
                    $connDev = trim($row['conn_device'] ?? '');
                    $label  = $connDev !== '' ? $connDev : ($alias !== '' ? $alias : '—');
                    $ts = !empty($row['poll_timestamp'])
                        ? date('d.m.Y H:i', strtotime($row['poll_timestamp'])) : '-';
                    $statusClass = ($row['oper_status'] === 'up') ? 'badge-up' : 'badge-down';
                    $statusText  = strtoupper($row['oper_status'] ?? 'UNKNOWN');

                    // Trafik
                    $inBytes  = (int)$row['in_octets'];
                    $outBytes = (int)$row['out_octets'];
                    $inBytesH  = formatBytes($inBytes);
                    $outBytesH = formatBytes($outBytes);

                    // Fiziksel katman analizi:
                    // in_errors (CRC/frame/runts) > 0 → kablo/SFP sorunu
                    $physOk = ($inErr === 0 && $outErr === 0);
                    $physLabel = $physOk
                        ? '<span class="phys-ok"><i class="fas fa-check-circle"></i>Fiziksel Sağlıklı</span>'
                        : '<span class="phys-warn"><i class="fas fa-exclamation-triangle"></i>Fiziksel Kontrol Et</span>';

                    // Tooltip içeriği (JSON-safe data attributes)
                    $ttPhysClass = $physOk ? 'tt-phys-ok' : 'tt-phys-warn';
                    $ttPhysMsg   = $physOk
                        ? '🟢 Fiziksel katman sağlıklı. Sorun SW yapısında (QoS / buffer / port hızı).'
                        : '🔴 Gelen hata var! Kablo, SFP veya port sorunlu olabilir.';

                    // data attributes for type filter
                    $typeAttr = '';
                    if ($inErr  > 0) $typeAttr .= ' in_errors';
                    if ($outErr > 0) $typeAttr .= ' out_errors';
                    if ($outDis > 0) $typeAttr .= ' out_discards';
                    $rowKey = htmlspecialchars('err:' . ($row['switch_name'] ?? '') . ':' . (int)$row['port_number']);
                ?>
                <tr data-switch="<?= htmlspecialchars($row['switch_name'] ?? '') ?>"
                    data-types="<?= trim($typeAttr) ?>"
                    data-rowkey="<?= $rowKey ?>">
                    <td>
                        <?= htmlspecialchars($row['switch_name'] ?? '-') ?>
                        <?php if (!empty($row['ip_address'])): ?>
                        <br><span style="color:var(--text-light);font-size:11px"><?= htmlspecialchars($row['ip_address']) ?></span>
                        <?php endif; ?>
                        <?php if (!empty($row['sw_model'])): ?>
                        <br><span style="color:var(--text-light);font-size:11px;font-style:italic"><?= htmlspecialchars($row['sw_model']) ?></span>
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
                    <td>
                        <div class="tooltip-wrap">
                            <span class="<?= $outDis > 0 ? 'val-warn' : 'val-zero' ?>"><?= number_format($outDis) ?></span>
                            <?php if ($outDis > 0): ?>
                            <div class="tt-box">
                                <h4><i class="fas fa-arrow-up"></i> Çıkış Drop Analizi</h4>
                                <div class="tt-row">
                                    <span class="<?= $ttPhysClass ?>"><?= $ttPhysMsg ?></span>
                                </div>
                                <hr class="tt-sep">
                                <div class="tt-row">
                                    <strong>↓ Gelen Hata:</strong> <?= number_format($inErr) ?><?= $inErr > 0 ? ' <span style="color:#f87171">⚠️</span>' : ' ✅' ?><br>
                                    <strong>↑ Giden Hata:</strong> <?= number_format($outErr) ?><?= $outErr > 0 ? ' <span style="color:#f87171">⚠️</span>' : ' ✅' ?><br>
                                    <strong>↓ Gelen Drop:</strong> <?= number_format($inDis) ?><br>
                                    <strong>↑ Çıkış Drop:</strong> <?= number_format($outDis) ?>
                                </div>
                                <hr class="tt-sep">
                                <div class="tt-cumul">⚠️ Bu sayaç SW reboot edilene kadar sıfırlanmaz (kümülatif).</div>
                            </div>
                            <?php endif; ?>
                        </div>
                    </td>
                    <td>
                        <div class="tooltip-wrap">
                            <span class="total-issues"><?= number_format($total) ?></span>
                            <div class="tt-box">
                                <h4><i class="fas fa-chart-bar"></i> Toplam Sorun Analizi</h4>
                                <div class="tt-row">
                                    <span class="<?= $ttPhysClass ?>"><?= $ttPhysMsg ?></span>
                                </div>
                                <hr class="tt-sep">
                                <div class="tt-row">
                                    <strong>↓ Gelen Hata:</strong> <?= number_format($inErr) ?><?= $inErr > 0 ? ' <span style="color:#f87171">⚠️</span>' : ' ✅' ?><br>
                                    <strong>↑ Giden Hata:</strong> <?= number_format($outErr) ?><?= $outErr > 0 ? ' <span style="color:#f87171">⚠️</span>' : ' ✅' ?><br>
                                    <strong>↑ Çıkış Drop:</strong> <?= number_format($outDis) ?>
                                </div>
                                <?php if ($inBytes > 0 || $outBytes > 0): ?>
                                <hr class="tt-sep">
                                <div class="tt-row">
                                    <span class="t-in">↓ Gelen Trafik: <?= $inBytesH ?></span><br>
                                    <span class="t-out">↑ Giden Trafik: <?= $outBytesH ?></span>
                                </div>
                                <?php endif; ?>
                                <hr class="tt-sep">
                                <div class="tt-cumul">⚠️ Sayaçlar kümülatif — SW reboot edilene kadar sıfırlanmaz.</div>
                            </div>
                        </div>
                    </td>
                    <td class="trafik-cell">
                        <span class="t-in">↓ <?= $inBytesH ?></span><br>
                        <span class="t-out">↑ <?= $outBytesH ?></span>
                    </td>
                    <td><?= $physLabel ?></td>
                    <td style="color:var(--text-light);font-size:11px"><?= $ts ?></td>
                    <td style="padding-right:6px">
                        <div class="action-cell">
                        <button class="btn-goto-port" onclick="gotoPort(<?= htmlspecialchars(json_encode($row['switch_name']), ENT_QUOTES) ?>,<?= (int)$row['port_number'] ?>)" title="Bu porta git"><i class="fas fa-plug"></i> Porta Git</button>
                        <button class="btn-hide-row" onclick="hideRow('<?= $rowKey ?>')" title="Bu satırı gizle"><i class="fas fa-eye-slash"></i> Gizle</button>
                        </div>
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
                hiddenRows = new Set(d.hidden.filter(k => k.startsWith('err:')));
                updateHideBtn();
                filterTable();
            }
        })
        .catch(() => {});
}
function saveHide(key) { fetch('../api/hidden_ports_api.php',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'hide',row_key:key})}).catch(()=>{}); }
function saveShow(key) { fetch('../api/hidden_ports_api.php',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'show',row_key:key})}).catch(()=>{}); }

function hideRow(key) { hiddenRows.add(key); saveHide(key); updateHideBtn(); updateRowButtons(); filterTable(); }
function showRow(key) { hiddenRows.delete(key); saveShow(key); if(!hiddenRows.size) showingHidden=false; updateHideBtn(); updateRowButtons(); filterTable(); }
function toggleHiddenView() { showingHidden=!showingHidden; updateHideBtn(); updateRowButtons(); filterTable(); }

function updateHideBtn() {
    const btn=document.getElementById('btnShowHidden'), label=document.getElementById('btnHideLabel'), icon=document.getElementById('btnHideIcon'), n=hiddenRows.size;
    if (showingHidden) { label.textContent='← Tüm Portlar'; icon.className='fas fa-list'; btn.disabled=false; btn.classList.add('active'); }
    else { label.textContent='Gizlileri Göster ('+n+')'; icon.className='fas fa-eye'; btn.disabled=n===0; btn.classList.toggle('active',n>0); }
}
function updateRowButtons() {
    document.querySelectorAll('#tableBody tr').forEach(tr => {
        const key=tr.dataset.rowkey||'', hideBtn=tr.querySelector('.btn-hide-row');
        if (!hideBtn) return;
        if (showingHidden) { hideBtn.innerHTML='<i class="fas fa-eye"></i> Göster'; hideBtn.onclick=()=>showRow(key); hideBtn.title='Bu satırı geri göster'; }
        else { hideBtn.innerHTML='<i class="fas fa-eye-slash"></i> Gizle'; hideBtn.onclick=()=>hideRow(key); hideBtn.title='Bu satırı gizle'; }
    });
}

// ── Filter ────────────────────────────────────────────────────────────────────
function filterTable() {
    const q=document.getElementById('searchInput').value.toLowerCase(), swF=document.getElementById('switchFilter').value, typeF=document.getElementById('typeFilter').value;
    const rows=document.querySelectorAll('#tableBody tr'); let visible=0;
    rows.forEach(tr => {
        const rowKey=tr.dataset.rowkey||'';
        let show;
        if (showingHidden) { show=hiddenRows.has(rowKey); }
        else {
            const matchQ=!q||tr.textContent.toLowerCase().includes(q), matchSw=!swF||tr.dataset.switch===swF, matchT=!typeF||(tr.dataset.types||'').includes(typeF);
            show=matchQ&&matchSw&&matchT&&!hiddenRows.has(rowKey);
        }
        tr.style.display=show?'':'none'; if(show) visible++;
    });
    const rc=document.getElementById('rowCount');
    if (rc) rc.innerHTML=showingHidden?`<strong>${visible}</strong> gizli kayıt listeleniyor.`:`<strong>${visible}</strong> port gösteriliyor.`;
}

document.addEventListener('DOMContentLoaded',function(){ loadHiddenRows(); updateHideBtn(); updateRowButtons();

    // Tooltip positioning: position fixed tooltip relative to mouse to avoid overflow
    document.querySelectorAll('.tooltip-wrap').forEach(function(wrap) {
        var box = wrap.querySelector('.tt-box');
        if (!box) return;
        wrap.addEventListener('mouseenter', function(e) {
            var rect = wrap.getBoundingClientRect();
            var vpW = window.innerWidth, vpH = window.innerHeight;
            var boxW = 290, boxH = 200; // estimated
            var top = rect.top - boxH - 8;
            var left = rect.left + rect.width / 2 - boxW / 2;
            if (top < 8) top = rect.bottom + 8;
            if (left < 8) left = 8;
            if (left + boxW > vpW - 8) left = vpW - boxW - 8;
            box.style.top  = top  + 'px';
            box.style.left = left + 'px';
        });
    });
});

// ── Sort ──────────────────────────────────────────────────────────────────────
let sortState = { col: -1, asc: true };
function sortTable(col) {
    const tbody=document.getElementById('tableBody'); if(!tbody) return;
    const rows=Array.from(tbody.querySelectorAll('tr')), asc=(sortState.col===col)?!sortState.asc:true;
    sortState={col,asc};
    rows.sort((a,b)=>{ const va=a.querySelectorAll('td')[col]?.textContent.trim().replace(/,/g,'')||'', vb=b.querySelectorAll('td')[col]?.textContent.trim().replace(/,/g,'')||''; const na=parseFloat(va),nb=parseFloat(vb), cmp=(!isNaN(na)&&!isNaN(nb))?na-nb:va.localeCompare(vb,'tr'); return asc?cmp:-cmp; });
    rows.forEach(r=>tbody.appendChild(r));
    document.querySelectorAll('thead th').forEach((th,i)=>{ th.classList.toggle('sorted',i===col); const icon=th.querySelector('.sort-icon'); if(icon) icon.className='sort-icon fas '+(i!==col?'fa-sort':asc?'fa-sort-up':'fa-sort-down'); });
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
function openDlModal() { document.getElementById('dlPassword').value=''; document.getElementById('dlPasswordError').style.display='none'; document.getElementById('dlPasswordModal').classList.add('show'); setTimeout(()=>document.getElementById('dlPassword').focus(),50); }
function closeDlModal() { document.getElementById('dlPasswordModal').classList.remove('show'); document.getElementById('dlPassword').value=''; document.getElementById('dlPasswordError').style.display='none'; }
document.getElementById('dlPasswordModal').addEventListener('click',function(e){ if(e.target===this) closeDlModal(); });
document.getElementById('dlPassword').addEventListener('keydown',function(e){ if(e.key==='Enter') confirmDownload(); });

async function confirmDownload() {
    const password=document.getElementById('dlPassword').value, errEl=document.getElementById('dlPasswordError'), btn=document.getElementById('dlConfirmBtn');
    if (!password) { errEl.textContent='Şifre boş olamaz.'; errEl.style.display='block'; document.getElementById('dlPassword').focus(); return; }
    btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Doğrulanıyor…'; errEl.style.display='none';
    try {
        const res=await fetch('../api/export_excel.php?type=errors',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});
        const data=await res.json();
        if (!data.success) { errEl.textContent=data.error||'Şifre hatalı.'; errEl.style.display='block'; btn.disabled=false; btn.innerHTML='<i class="fas fa-file-excel"></i> İndir'; document.getElementById('dlPassword').focus(); document.getElementById('dlPassword').select(); return; }
        closeDlModal(); window.location.href='../api/export_excel.php?type=errors';
    } catch(e) { errEl.textContent='Sunucu hatası. Lütfen tekrar deneyin.'; errEl.style.display='block'; btn.disabled=false; btn.innerHTML='<i class="fas fa-file-excel"></i> İndir'; }
}
</script>
</body>
</html>
