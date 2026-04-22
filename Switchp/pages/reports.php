<?php
/**
 * reports.php — Raporlar Merkezi
 *
 * Tüm analiz/rapor sayfalarına hızlı erişim sağlar ve
 * ağda 100 Mbps ve altında çalışan (UP) portları listeler.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();
session_write_close();

header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// ── 100 Mbps ve altındaki UP portları ──────────────────────────────────────
// port_speed bps cinsinden saklanır. 100 Mbps = 100 000 000 bps
$sql = "
    SELECT
        sd.name           AS switch_name,
        psd.port_number,
        psd.port_alias    AS alias,
        psd.mac_address   AS port_mac,
        psd.vlan_id,
        psd.oper_status,
        psd.port_speed,
        psd.poll_timestamp,
        mdr.device_name   AS conn_device,
        mdr.ip_address    AS conn_ip
    FROM port_status_data psd
    JOIN snmp_devices sd ON sd.id = psd.device_id
    LEFT JOIN mac_device_registry mdr ON mdr.mac_address = psd.mac_address
    WHERE psd.oper_status = 'up'
      AND psd.port_speed IS NOT NULL
      AND psd.port_speed > 0
      AND psd.port_speed <= 100000000
    ORDER BY psd.port_speed ASC, sd.name, psd.port_number
";

$result  = $conn->query($sql);
$ports   = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
$portCnt = count($ports);

// Hız grupları (özet)
$speedGroups = [];
foreach ($ports as $p) {
    $mbps = (int)round($p['port_speed'] / 1000000);
    $key  = $mbps . ' Mbps';
    $speedGroups[$key] = ($speedGroups[$key] ?? 0) + 1;
}
ksort($speedGroups);

// Switch bazında kaç port
$switchGroups = [];
foreach ($ports as $p) {
    $switchGroups[$p['switch_name']] = ($switchGroups[$p['switch_name']] ?? 0) + 1;
}
arsort($switchGroups);

// Benzersiz VLAN ID'leri (filtre için)
$vlanList = [];
foreach ($ports as $p) {
    if ($p['vlan_id'] !== null && $p['vlan_id'] !== '') {
        $vlanList[(int)$p['vlan_id']] = true;
    }
}
ksort($vlanList);

/**
 * bps → insan okunabilir hız dizesi
 */
function formatSpeed(int $bps): string {
    if ($bps >= 1_000_000_000) return round($bps / 1_000_000_000, 1) . ' Gbps';
    if ($bps >= 1_000_000)     return round($bps / 1_000_000,     1) . ' Mbps';
    if ($bps >= 1_000)         return round($bps / 1_000,         1) . ' Kbps';
    return $bps . ' bps';
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Raporlar</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
    <style>
        :root {
            --primary:      #3b82f6;
            --primary-dark: #2563eb;
            --success:      #10b981;
            --warning:      #f59e0b;
            --danger:       #ef4444;
            --dark:         #0f172a;
            --dark-light:   #1e293b;
            --nav-bg:       rgba(15,23,42,0.97);
            --text:         #e2e8f0;
            --text-light:   #94a3b8;
            --border:       #334155;
            --nav-h:        58px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { height: 100%; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--dark);
            color: var(--text);
            overflow-x: hidden;
        }

        /* ═══════════════════════════════════════════════════════
           STICKY TOP NAV
        ═══════════════════════════════════════════════════════ */
        .top-nav {
            position: sticky;
            top: 0;
            z-index: 1000;
            height: var(--nav-h);
            background: var(--nav-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 0;
            padding: 0 16px;
            overflow-x: auto;
            overflow-y: hidden;
            scrollbar-width: thin;
            scrollbar-color: #334155 transparent;
        }
        .top-nav::-webkit-scrollbar { height: 3px; }
        .top-nav::-webkit-scrollbar-track { background: transparent; }
        .top-nav::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }

        .nav-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 0 14px 0 4px;
            border-right: 1px solid var(--border);
            margin-right: 10px;
            flex-shrink: 0;
            white-space: nowrap;
        }
        .nav-brand i { color: var(--primary); font-size: 18px; }
        .nav-brand span { font-size: 14px; font-weight: 700; color: var(--text); letter-spacing: 0.3px; }

        .nav-btn {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            padding: 7px 13px;
            border-radius: 8px;
            border: 1px solid transparent;
            background: transparent;
            color: var(--text-light);
            font-size: 12.5px;
            font-weight: 500;
            cursor: pointer;
            white-space: nowrap;
            flex-shrink: 0;
            transition: color 0.15s, background 0.15s, border-color 0.15s;
            text-decoration: none;
            margin: 0 2px;
        }
        .nav-btn i { font-size: 13px; flex-shrink: 0; }
        .nav-btn:hover {
            color: var(--text);
            background: rgba(255,255,255,0.06);
            border-color: var(--border);
        }
        .nav-btn.active {
            color: #fff;
            background: rgba(59,130,246,0.18);
            border-color: rgba(59,130,246,0.5);
        }
        .nav-btn.active i { color: var(--primary); }

        /* Renk aksan noktası */
        .nav-btn .dot {
            width: 6px; height: 6px;
            border-radius: 50%;
            flex-shrink: 0;
        }

        .nav-spacer { flex: 1; min-width: 8px; }

        .nav-refresh {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: transparent;
            color: var(--text-light);
            font-size: 12px;
            cursor: pointer;
            white-space: nowrap;
            flex-shrink: 0;
            transition: color 0.15s, border-color 0.15s;
        }
        .nav-refresh:hover { color: var(--primary); border-color: var(--primary); }

        /* ═══════════════════════════════════════════════════════
           PANEL WRAPPER
        ═══════════════════════════════════════════════════════ */
        .panel-wrapper {
            height: calc(100vh - var(--nav-h));
            position: relative;
        }

        /* Built-in slow-ports panel */
        .panel-native {
            height: 100%;
            overflow-y: auto;
            padding: 24px 24px 32px;
            display: none;
        }
        .panel-native.active { display: block; }

        /* Iframe panel */
        .panel-iframe {
            height: 100%;
            display: none;
        }
        .panel-iframe.active { display: block; }
        .panel-iframe iframe {
            width: 100%;
            height: 100%;
            border: none;
        }

        /* Breadcrumb strip inside native panel */
        .breadcrumb {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 18px;
            font-size: 12px;
            color: var(--text-light);
        }
        .breadcrumb i { color: var(--primary); }
        .breadcrumb strong { color: var(--text); }

        /* ═══════════════════════════════════════════════════════
           STATS + TABLE (within native panel)
        ═══════════════════════════════════════════════════════ */
        .section-title {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-light);
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .section-title i { color: var(--primary); }

        .stats-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 14px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--dark-light);
            padding: 18px;
            border-radius: 10px;
            border: 1px solid var(--border);
            text-align: center;
        }
        .stat-card .num   { font-size: 30px; font-weight: 700; margin-bottom: 4px; }
        .stat-card .label { font-size: 11px; color: var(--text-light); text-transform: uppercase; letter-spacing: 1px; }
        .stat-card.warn   .num { color: var(--warning); }
        .stat-card.info   .num { color: var(--primary); }
        .stat-card.danger .num { color: var(--danger); }

        .chip-bar {
            background: var(--dark-light);
            padding: 12px 16px;
            border-radius: 10px;
            border: 1px solid var(--border);
            margin-bottom: 14px;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }
        .chip-bar .label {
            font-size: 11px;
            color: var(--text-light);
            text-transform: uppercase;
            letter-spacing: 1px;
            flex-shrink: 0;
            margin-right: 4px;
        }
        .chip { padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .chip-speed  { background:#2d1f07; color:#fbbf24; border:1px solid #d97706; }
        .chip-switch { background:#0f1f3a; color:#93c5fd; border:1px solid #1d4ed8; }

        .toolbar {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            margin-bottom: 14px;
        }
        .search-box { position: relative; flex: 1; min-width: 200px; }
        .search-box i {
            position: absolute; left: 10px; top: 50%;
            transform: translateY(-50%);
            color: var(--text-light); font-size: 12px;
        }
        .search-box input {
            width: 100%;
            padding: 8px 10px 8px 32px;
            background: var(--dark-light);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 13px;
            outline: none;
        }
        .search-box input:focus { border-color: var(--primary); }
        select.filter-select {
            padding: 8px 10px;
            background: var(--dark-light);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 13px;
            outline: none;
            cursor: pointer;
        }
        select.filter-select:focus { border-color: var(--primary); }
        .btn {
            padding: 8px 14px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .btn-secondary {
            background: var(--dark-light);
            border: 1px solid var(--border);
            color: var(--text);
        }
        .btn-secondary:hover { border-color: var(--primary); color: var(--primary); }
        .btn-secondary.active { border-color: var(--warning); color: var(--warning); background: rgba(245,158,11,0.08); }

        .table-wrap {
            background: var(--dark-light);
            border-radius: 12px;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        table { width: 100%; border-collapse: collapse; }
        thead th {
            background: #0f1f3a;
            padding: 11px 14px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-light);
            text-align: left;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
            cursor: pointer;
            user-select: none;
        }
        thead th:hover { color: var(--primary); }
        thead th .sort-icon { margin-left: 4px; opacity: 0.4; font-size: 10px; }
        thead th.sorted .sort-icon { opacity: 1; color: var(--primary); }
        tbody tr { border-bottom: 1px solid #1e2a3a; transition: background 0.15s; }
        tbody tr:last-child { border-bottom: none; }
        tbody tr:hover { background: #1a2a40; }
        tbody td { padding: 10px 14px; font-size: 13px; }

        .badge { display:inline-block; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700; letter-spacing:0.5px; }
        .badge-up   { background:#0d2b1a; color:#4ade80; border:1px solid #16a34a; }
        .badge-vlan { background:#0f1f3a; color:#93c5fd; border:1px solid #1d4ed8; }
        .speed-warn { color: var(--warning); font-weight: 700; }
        .speed-10   { color: var(--danger);  font-weight: 700; }

        .empty-state { text-align:center; padding:60px 20px; color:var(--text-light); }
        .empty-state i  { font-size:48px; color:var(--success); margin-bottom:16px; display:block; }
        .empty-state h2 { font-size:20px; color:var(--success); margin-bottom:8px; }
        .row-count { font-size:12px; color:var(--text-light); padding:8px 14px; border-top:1px solid var(--border); }

        /* Loading spinner for iframe */
        .iframe-loading {
            position: absolute;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--dark);
            flex-direction: column;
            gap: 16px;
            color: var(--text-light);
            font-size: 14px;
        }
        .spinner {
            width: 40px; height: 40px;
            border: 3px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        @media (max-width: 768px) {
            .stats-bar { grid-template-columns: repeat(2,1fr); }
            .panel-native { padding: 14px; }
        }
    </style>
</head>
<body>

<!-- ══════════════════════════════════════════════════════════
     STICKY TOP NAVIGATION BAR
═══════════════════════════════════════════════════════════ -->
<nav class="top-nav" id="topNav">

    <div class="nav-brand">
        <i class="fas fa-chart-bar"></i>
        <span>Raporlar</span>
    </div>

    <!-- Built-in Slow Ports -->
    <button class="nav-btn active" id="btn-slowports" onclick="showNative(this)"
            data-label="Yavaş Portlar">
        <i class="fas fa-tachometer-alt" style="color:#f59e0b"></i>
        Yavaş Portlar
    </button>

    <!-- Separator -->
    <span style="color:var(--border);font-size:16px;margin:0 4px;flex-shrink:0">|</span>

    <!-- Iframe reports -->
    <button class="nav-btn" onclick="loadFrame(this,'vlan_alias_check.php')"
            data-label="VLAN/Alias Uyumsuzluk">
        <i class="fas fa-exclamation-triangle" style="color:#f59e0b"></i>
        VLAN/Alias Uyumsuzluk
    </button>
    <button class="nav-btn" onclick="loadFrame(this,'matris.php')"
            data-label="Alarm Matrisi">
        <i class="fas fa-table" style="color:#8b5cf6"></i>
        Alarm Matrisi
    </button>
    <button class="nav-btn" onclick="loadFrame(this,'port_alarms.php')"
            data-label="Port Alarmları">
        <i class="fas fa-bell" style="color:#ef4444"></i>
        Port Alarmları
    </button>
    <button class="nav-btn" onclick="loadFrame(this,'admin_mac_history.php')"
            data-label="MAC Değişim">
        <i class="fas fa-history" style="color:#3b82f6"></i>
        MAC Değişim
    </button>
    <button class="nav-btn" onclick="loadFrame(this,'device_import.php')"
            data-label="Cihaz Envanteri">
        <i class="fas fa-laptop" style="color:#10b981"></i>
        Cihaz Envanteri
    </button>
    <button class="nav-btn" onclick="loadFrame(this,'mac_bulk_fix.php')"
            data-label="MAC Toplu Düzeltme">
        <i class="fas fa-tools" style="color:#3b82f6"></i>
        MAC Toplu Düzeltme
    </button>

    <span style="color:var(--border);font-size:16px;margin:0 4px;flex-shrink:0">|</span>

    <button class="nav-btn" onclick="loadFrame(this,'report_vlan_dist.php')"
            data-label="VLAN Dağılımı">
        <i class="fas fa-layer-group" style="color:#a78bfa"></i>
        VLAN Dağılımı
    </button>
    <button class="nav-btn" onclick="loadFrame(this,'report_flapping.php')"
            data-label="Up/Down Döngüsü">
        <i class="fas fa-exchange-alt" style="color:#ef4444"></i>
        Up/Down Döngüsü
    </button>
    <button class="nav-btn" onclick="loadFrame(this,'report_errors.php')"
            data-label="Hata / Drop">
        <i class="fas fa-bug" style="color:#f59e0b"></i>
        Hata / Drop
    </button>

    <div class="nav-spacer"></div>

    <button class="nav-refresh" id="btnRefresh" onclick="refreshCurrent()" title="Sayfayı yenile">
        <i class="fas fa-sync-alt"></i> Yenile
    </button>

</nav>

<!-- ══════════════════════════════════════════════════════════
     PANEL WRAPPER
═══════════════════════════════════════════════════════════ -->
<div class="panel-wrapper">

    <!-- ── Native panel: 100 Mbps ve Altı ───────────────────── -->
    <div class="panel-native active" id="panel-native">

        <div class="breadcrumb">
            <i class="fas fa-tachometer-alt"></i>
            <strong>100 Mbps ve Altında Çalışan UP Portlar</strong>
            <span style="margin-left:auto;color:var(--text-light)">
                Son yenileme: <?= date('d.m.Y H:i:s') ?>
            </span>
        </div>

        <!-- Stats -->
        <div class="stats-bar">
            <div class="stat-card warn" id="statSlowPorts">
                <div class="num" id="statSlowPortsNum"><?= $portCnt ?></div>
                <div class="label">Yavaş Port</div>
            </div>
            <div class="stat-card info">
                <div class="num"><?= count($speedGroups) ?></div>
                <div class="label">Farklı Hız</div>
            </div>
            <div class="stat-card info">
                <div class="num"><?= count($switchGroups) ?></div>
                <div class="label">Etkilenen Switch</div>
            </div>
            <?php
            $cnt10 = count(array_filter($ports, fn($p) => $p['port_speed'] <= 10_000_000));
            ?>
            <div class="stat-card <?= $cnt10 > 0 ? 'danger' : 'info' ?>" id="statTenMbps">
                <div class="num" id="statTenMbpsNum"><?= $cnt10 ?></div>
                <div class="label">10 Mbps ve Altı</div>
            </div>
        </div>

        <?php if (!empty($speedGroups)): ?>
        <div class="chip-bar">
            <span class="label"><i class="fas fa-bolt"></i>&nbsp; Hız Dağılımı</span>
            <?php foreach ($speedGroups as $speed => $cnt): ?>
                <span class="chip chip-speed"><?= htmlspecialchars($speed) ?> &nbsp;<strong><?= $cnt ?></strong></span>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <?php if (!empty($switchGroups)): ?>
        <div class="chip-bar">
            <span class="label"><i class="fas fa-server"></i>&nbsp; Switch</span>
            <?php foreach ($switchGroups as $sw => $cnt): ?>
                <span class="chip chip-switch"><?= htmlspecialchars($sw) ?> &nbsp;<strong><?= $cnt ?></strong></span>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <!-- Toolbar -->
        <div class="toolbar">
            <div class="search-box">
                <i class="fas fa-search"></i>
                <input type="text" id="searchInput" placeholder="Switch, port veya alias ara…" oninput="filterTable()">
            </div>
            <select class="filter-select" id="switchFilter" onchange="filterTable()">
                <option value="">Tüm Switch'ler</option>
                <?php foreach (array_keys($switchGroups) as $sw): ?>
                    <option value="<?= htmlspecialchars($sw) ?>"><?= htmlspecialchars($sw) ?></option>
                <?php endforeach; ?>
            </select>
            <select class="filter-select" id="speedFilter" onchange="filterTable()">
                <option value="">Tüm Hızlar</option>
                <?php foreach (array_keys($speedGroups) as $speed): ?>
                    <option value="<?= htmlspecialchars($speed) ?>"><?= htmlspecialchars($speed) ?></option>
                <?php endforeach; ?>
            </select>
            <select class="filter-select" id="vlanFilter" onchange="filterTable()">
                <option value="50_70" selected>VLAN 50 + 70</option>
                <option value="">Tüm VLAN'lar</option>
                <?php foreach (array_keys($vlanList) as $vlanId): ?>
                    <option value="<?= $vlanId ?>"><?= $vlanId ?></option>
                <?php endforeach; ?>
            </select>
            <button class="btn btn-secondary" id="btn100Toggle" onclick="toggle100()" title="100 Mbps portları gizle / göster">
                <i class="fas fa-eye-slash"></i> <span id="btn100Label">100 Mbps Gizle</span>
            </button>
            <button class="btn btn-secondary" onclick="exportXLSX()">
                <i class="fas fa-file-excel"></i> Excel
            </button>
        </div>

        <!-- Table -->
        <div class="table-wrap">
            <?php if (empty($ports)): ?>
                <div class="empty-state">
                    <i class="fas fa-check-circle"></i>
                    <h2>Yavaş Port Yok!</h2>
                    <p>Tüm UP portlar 100 Mbps'in üzerinde çalışıyor.</p>
                </div>
            <?php else: ?>
            <table id="speedTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Switch Adı <span class="sort-icon fas fa-sort"></span></th>
                        <th onclick="sortTable(1)">Port <span class="sort-icon fas fa-sort"></span></th>
                        <th onclick="sortTable(2)">Hız <span class="sort-icon fas fa-sort"></span></th>
                        <th onclick="sortTable(3)">VLAN <span class="sort-icon fas fa-sort"></span></th>
                        <th onclick="sortTable(4)">Bağlantı <span class="sort-icon fas fa-sort"></span></th>
                        <th onclick="sortTable(5)">Durum <span class="sort-icon fas fa-sort"></span></th>
                        <th onclick="sortTable(6)">Son Güncelleme <span class="sort-icon fas fa-sort"></span></th>
                    </tr>
                </thead>
                <tbody id="tableBody">
                    <?php foreach ($ports as $row):
                        $bps           = (int)$row['port_speed'];
                        $speedStr      = formatSpeed($bps);
                        $speedGroupKey = (int)round($bps / 1_000_000) . ' Mbps';
                        $speedClass    = ($bps <= 10_000_000) ? 'speed-10' : 'speed-warn';
                        $ts = !empty($row['poll_timestamp'])
                            ? date('d.m.Y H:i', strtotime($row['poll_timestamp']))
                            : '-';
                        $connDevice = trim($row['conn_device'] ?? '');
                        $connIp     = trim($row['conn_ip']     ?? '');
                        $alias      = trim($row['alias']       ?? '');
                        $portMac    = trim($row['port_mac']    ?? '');
                        $aliasIsGeneric = preg_match('/^(DEVICE|CIHAZ\s*\d*)$/i', $alias);
                        $label = $connDevice !== '' ? $connDevice : (!$aliasIsGeneric && $alias !== '' ? $alias : $portMac);
                        if ($label !== '' && $connIp !== '') {
                            $connHtml = htmlspecialchars($label) . '<br><span style="color:var(--text-light);font-size:11px">' . htmlspecialchars($connIp) . '</span>';
                        } elseif ($label !== '') {
                            $connHtml = htmlspecialchars($label);
                        } elseif ($connIp !== '') {
                            $connHtml = '<span style="color:var(--text-light);font-size:11px">' . htmlspecialchars($connIp) . '</span>';
                        } else {
                            $connHtml = '<span style="color:#475569">—</span>';
                        }
                    ?>
                    <tr data-switch="<?= htmlspecialchars($row['switch_name']) ?>"
                        data-speed="<?= htmlspecialchars($speedGroupKey) ?>"
                        data-vlan="<?= $row['vlan_id'] !== null ? (int)$row['vlan_id'] : '' ?>">
                        <td><?= htmlspecialchars($row['switch_name'] ?? '-') ?></td>
                        <td><?= (int)$row['port_number'] ?></td>
                        <td><span class="<?= $speedClass ?>"><?= htmlspecialchars($speedStr) ?></span></td>
                        <td><?= $row['vlan_id'] ? '<span class="badge badge-vlan">' . (int)$row['vlan_id'] . '</span>' : '-' ?></td>
                        <td style="font-size:12px;line-height:1.4"><?= $connHtml ?></td>
                        <td><span class="badge badge-up">UP</span></td>
                        <td style="color:var(--text-light)"><?= $ts ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <div class="row-count" id="rowCount">
                Toplam <strong><?= $portCnt ?></strong> yavaş port gösteriliyor.
            </div>
            <?php endif; ?>
        </div>

    </div><!-- /panel-native -->

    <!-- ── Iframe panel ──────────────────────────────────────── -->
    <div class="panel-iframe" id="panel-iframe">
        <div class="iframe-loading" id="iframeLoading">
            <div class="spinner"></div>
            <span>Yükleniyor…</span>
        </div>
        <iframe id="reportFrame" src="about:blank" onload="onFrameLoad()"></iframe>
    </div>

</div><!-- /panel-wrapper -->

<script>
// ── Panel switching ──────────────────────────────────────────────────────────
let currentFrameUrl = '';

function setActiveBtn(btn) {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
}

function showNative(btn) {
    setActiveBtn(btn);
    document.getElementById('panel-native').classList.add('active');
    document.getElementById('panel-iframe').classList.remove('active');
}

function loadFrame(btn, url) {
    setActiveBtn(btn);
    document.getElementById('panel-native').classList.remove('active');

    const panel  = document.getElementById('panel-iframe');
    const frame  = document.getElementById('reportFrame');
    const loading = document.getElementById('iframeLoading');

    panel.classList.add('active');

    // show spinner
    loading.style.display = 'flex';
    frame.style.opacity = '0';

    currentFrameUrl = url;
    frame.src = url;
}

function onFrameLoad() {
    const loading = document.getElementById('iframeLoading');
    const frame   = document.getElementById('reportFrame');
    loading.style.display = 'none';
    frame.style.opacity = '1';
    frame.style.transition = 'opacity 0.2s';
}

function refreshCurrent() {
    const nativeActive = document.getElementById('panel-native').classList.contains('active');
    if (nativeActive) {
        location.reload();
    } else {
        const frame = document.getElementById('reportFrame');
        const loading = document.getElementById('iframeLoading');
        loading.style.display = 'flex';
        frame.style.opacity = '0';
        frame.src = frame.src;  // reload iframe
    }
}

// ── 100 Mbps toggle ──────────────────────────────────────────────────────────
let hide100 = false;   // default: show all (100 Mbps rows visible)

function toggle100() {
    hide100 = !hide100;
    const btn   = document.getElementById('btn100Toggle');
    const label = document.getElementById('btn100Label');
    const icon  = btn.querySelector('i');
    if (hide100) {
        label.textContent = '100 Mbps Göster';
        icon.className    = 'fas fa-eye';
        btn.classList.add('active');
    } else {
        label.textContent = '100 Mbps Gizle';
        icon.className    = 'fas fa-eye-slash';
        btn.classList.remove('active');
    }
    filterTable();
}

// ── Filter ───────────────────────────────────────────────────────────────────
function filterTable() {
    const q          = document.getElementById('searchInput').value.toLowerCase();
    const swFilter   = document.getElementById('switchFilter').value;
    const spFilter   = document.getElementById('speedFilter').value;
    const vlanFilter = document.getElementById('vlanFilter').value;
    const rows       = document.querySelectorAll('#tableBody tr');
    let visible = 0, visible10 = 0;

    rows.forEach(tr => {
        const text      = tr.textContent.toLowerCase();
        const rowSwitch = tr.dataset.switch || '';
        const rowSpeed  = tr.dataset.speed  || '';
        const rowVlan   = tr.dataset.vlan   || '';

        const matchQ  = !q        || text.includes(q);
        const matchSw = !swFilter || rowSwitch === swFilter;
        const matchSp = !spFilter || rowSpeed  === spFilter;
        let matchVlan = true;
        if (vlanFilter === '50_70') {
            matchVlan = rowVlan === '50' || rowVlan === '70';
        } else if (vlanFilter !== '') {
            matchVlan = rowVlan === vlanFilter;
        }
        // hide exactly-100 Mbps rows when toggle is on
        const is100   = rowSpeed === '100 Mbps';
        const match100 = !(hide100 && is100);

        const show = matchQ && matchSw && matchSp && matchVlan && match100;
        tr.style.display = show ? '' : 'none';
        if (show) {
            visible++;
            const spd = rowSpeed.replace(' Mbps','');
            if (!isNaN(spd) && parseInt(spd) <= 10) visible10++;
        }
    });

    const rc = document.getElementById('rowCount');
    if (rc) rc.innerHTML = `<strong>${visible}</strong> kayıt gösteriliyor.`;

    const slowNum  = document.getElementById('statSlowPortsNum');
    const tenNum   = document.getElementById('statTenMbpsNum');
    const slowCard = document.getElementById('statSlowPorts');
    if (slowNum) slowNum.textContent = visible;
    if (slowCard) {
        slowCard.classList.toggle('warn', visible > 0);
        slowCard.classList.toggle('info', visible === 0);
    }
    if (tenNum) tenNum.textContent = visible10;
}

document.addEventListener('DOMContentLoaded', function() {
    filterTable();
});

// ── Sort ─────────────────────────────────────────────────────────────────────
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
        if (col === 2) {
            return asc ? parseSpeed(va) - parseSpeed(vb) : parseSpeed(vb) - parseSpeed(va);
        }
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

function parseSpeed(str) {
    const m = str.match(/([\d.]+)\s*(Gbps|Mbps|Kbps|bps)/i);
    if (!m) return 0;
    const v = parseFloat(m[1]);
    switch (m[2].toLowerCase()) {
        case 'gbps': return v * 1e9;
        case 'mbps': return v * 1e6;
        case 'kbps': return v * 1e3;
        default:     return v;
    }
}

// ── Excel Export ─────────────────────────────────────────────────────────────
function exportXLSX() {
    const headers = ['Switch Adı','Port','Hız','VLAN','Bağlantı','Durum','Son Güncelleme'];
    const rows    = Array.from(document.querySelectorAll('#tableBody tr'))
        .filter(r => r.style.display !== 'none')
        .map(r => Array.from(r.querySelectorAll('td')).map(td => td.textContent.trim()));
    const ws = XLSX.utils.aoa_to_sheet([headers, ...rows]);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Yavaş Portlar');
    XLSX.writeFile(wb, 'dusuk_hizli_portlar_' + new Date().toISOString().slice(0,10) + '.xlsx');
}
</script>
</body>
</html>
