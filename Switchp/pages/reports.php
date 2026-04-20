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
        psd.vlan_id,
        psd.oper_status,
        psd.port_speed,
        psd.poll_timestamp,
        mat.device_name   AS conn_device,
        mat.ip_address    AS conn_ip
    FROM port_status_data psd
    JOIN snmp_devices sd ON sd.id = psd.device_id
    LEFT JOIN mac_address_tracking mat
           ON mat.current_device_id   = psd.device_id
          AND mat.current_port_number = psd.port_number
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
        html { zoom: 0.95; }
        :root {
            --primary:      #3b82f6;
            --primary-dark: #2563eb;
            --success:      #10b981;
            --warning:      #f59e0b;
            --danger:       #ef4444;
            --dark:         #0f172a;
            --dark-light:   #1e293b;
            --text:         #e2e8f0;
            --text-light:   #94a3b8;
            --border:       #334155;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--dark);
            color: var(--text);
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }

        /* ── Header ── */
        .header {
            background: var(--dark-light);
            padding: 25px 30px;
            border-radius: 15px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .header-icon { font-size: 36px; color: var(--primary); flex-shrink: 0; }
        .header h1   { color: var(--primary); font-size: 24px; margin-bottom: 6px; }
        .header p    { color: var(--text-light); font-size: 13px; line-height: 1.5; }

        /* ── Rapor Kartları ── */
        .section-title {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-light);
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .section-title i { color: var(--primary); }

        .report-cards {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }
        .report-card {
            background: var(--dark-light);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 10px;
            text-decoration: none;
            color: var(--text);
            transition: border-color 0.2s, transform 0.15s, box-shadow 0.2s;
        }
        .report-card:hover {
            border-color: var(--primary);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(59,130,246,0.15);
            color: var(--text);
            text-decoration: none;
        }
        .report-card .card-icon {
            font-size: 28px;
            margin-bottom: 2px;
        }
        .report-card .card-title { font-size: 15px; font-weight: 600; }
        .report-card .card-desc  { font-size: 12px; color: var(--text-light); line-height: 1.5; }
        .report-card .card-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            width: fit-content;
        }
        .badge-blue   { background:#0f1f3a; color:#93c5fd; border:1px solid #1d4ed8; }
        .badge-yellow { background:#2d1f07; color:#fbbf24; border:1px solid #d97706; }
        .badge-red    { background:#2b0d0d; color:#f87171; border:1px solid #b91c1c; }
        .badge-purple { background:#1a0d2b; color:#c4b5fd; border:1px solid #7c3aed; }
        .badge-green  { background:#0d2b1a; color:#4ade80; border:1px solid #16a34a; }

        /* ── Stats bar ── */
        .stats-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--dark-light);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
            text-align: center;
        }
        .stat-card .num   { font-size: 32px; font-weight: 700; margin-bottom: 4px; }
        .stat-card .label { font-size: 12px; color: var(--text-light); text-transform: uppercase; letter-spacing: 1px; }
        .stat-card.warn .num  { color: var(--warning); }
        .stat-card.info .num  { color: var(--primary); }
        .stat-card.danger .num { color: var(--danger); }

        /* ── Speed/Switch chips ── */
        .chip-bar {
            background: var(--dark-light);
            padding: 14px 18px;
            border-radius: 10px;
            border: 1px solid var(--border);
            margin-bottom: 16px;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }
        .chip-bar .label {
            font-size: 12px;
            color: var(--text-light);
            text-transform: uppercase;
            letter-spacing: 1px;
            flex-shrink: 0;
            margin-right: 4px;
        }
        .chip {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .chip-speed  { background:#2d1f07; color:#fbbf24; border:1px solid #d97706; }
        .chip-switch { background:#0f1f3a; color:#93c5fd; border:1px solid #1d4ed8; }

        /* ── Toolbar ── */
        .toolbar {
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .search-box { position: relative; flex: 1; min-width: 220px; }
        .search-box i {
            position: absolute; left: 12px; top: 50%;
            transform: translateY(-50%);
            color: var(--text-light); font-size: 13px;
        }
        .search-box input {
            width: 100%;
            padding: 9px 12px 9px 34px;
            background: var(--dark-light);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 13px;
            outline: none;
        }
        .search-box input:focus { border-color: var(--primary); }
        select.filter-select {
            padding: 9px 12px;
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
            padding: 9px 16px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
            text-decoration: none;
        }
        .btn-secondary {
            background: var(--dark-light);
            border: 1px solid var(--border);
            color: var(--text);
        }
        .btn-secondary:hover { border-color: var(--primary); color: var(--primary); }

        /* ── Table ── */
        .table-wrap {
            background: var(--dark-light);
            border-radius: 12px;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        table { width: 100%; border-collapse: collapse; }
        thead th {
            background: #0f1f3a;
            padding: 12px 16px;
            font-size: 12px;
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
        tbody td { padding: 11px 16px; font-size: 13px; }

        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }
        .badge-up   { background:#0d2b1a; color:#4ade80; border:1px solid #16a34a; }
        .badge-vlan { background:#0f1f3a; color:#93c5fd; border:1px solid #1d4ed8; }
        .speed-warn { color: var(--warning); font-weight: 700; }
        .speed-10   { color: var(--danger);  font-weight: 700; }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-light);
        }
        .empty-state i  { font-size: 48px; color: var(--success); margin-bottom: 16px; display: block; }
        .empty-state h2 { font-size: 20px; color: var(--success); margin-bottom: 8px; }

        .row-count {
            font-size: 12px;
            color: var(--text-light);
            padding: 8px 16px;
            border-top: 1px solid var(--border);
        }

        .divider {
            border: none;
            border-top: 1px solid var(--border);
            margin: 28px 0;
        }

        @media (max-width: 768px) {
            .stats-bar { grid-template-columns: repeat(2,1fr); }
            .report-cards { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="header">
        <div class="header-icon"><i class="fas fa-chart-bar"></i></div>
        <div>
            <h1>Raporlar</h1>
            <p>
                Ağ analiz araçlarına hızlı erişim &amp; canlı raporlar.
                &nbsp;·&nbsp; Son yenileme: <strong><?= date('d.m.Y H:i:s') ?></strong>
            </p>
        </div>
    </div>

    <!-- ── Rapor Kartları ─────────────────────────────────────────── -->
    <div class="section-title">
        <i class="fas fa-th-large"></i> Rapor Sayfaları
    </div>
    <div class="report-cards">

        <a class="report-card" href="vlan_alias_check.php" target="_blank">
            <div class="card-icon" style="color:#f59e0b"><i class="fas fa-exclamation-triangle"></i></div>
            <div class="card-title">VLAN / Alias Uyumsuzluk</div>
            <div class="card-desc">Port alias'larının VLAN tipiyle çelişip çelişmediğini kontrol eder.</div>
            <span class="card-badge badge-yellow"><i class="fas fa-external-link-alt"></i> Aç</span>
        </a>

        <a class="report-card" href="matris.php" target="_blank">
            <div class="card-icon" style="color:#8b5cf6"><i class="fas fa-table"></i></div>
            <div class="card-title">Alarm Matrisi</div>
            <div class="card-desc">Sistemin tüm alarm türlerini, tetiklenme mantığını ve istatistiklerini gösterir.</div>
            <span class="card-badge badge-purple"><i class="fas fa-external-link-alt"></i> Aç</span>
        </a>

        <a class="report-card" href="port_alarms.php" target="_blank">
            <div class="card-icon" style="color:#ef4444"><i class="fas fa-bell"></i></div>
            <div class="card-title">Port Alarmları</div>
            <div class="card-desc">Aktif port alarmlarını, önem derecelerini ve onay durumlarını listeler.</div>
            <span class="card-badge badge-red"><i class="fas fa-external-link-alt"></i> Aç</span>
        </a>

        <a class="report-card" href="admin_mac_history.php" target="_blank">
            <div class="card-icon" style="color:#3b82f6"><i class="fas fa-history"></i></div>
            <div class="card-title">MAC Değişim Geçmişi</div>
            <div class="card-desc">Port bazlı MAC adres değişim kayıtlarını ve hareket geçmişini gösterir.</div>
            <span class="card-badge badge-blue"><i class="fas fa-external-link-alt"></i> Aç</span>
        </a>

        <a class="report-card" href="device_import.php" target="_blank">
            <div class="card-icon" style="color:#10b981"><i class="fas fa-laptop"></i></div>
            <div class="card-title">Cihaz Envanteri</div>
            <div class="card-desc">Ağdaki kayıtlı cihazlar, MAC adresleri ve kullanıcı bilgileri.</div>
            <span class="card-badge badge-green"><i class="fas fa-external-link-alt"></i> Aç</span>
        </a>

        <a class="report-card" href="mac_bulk_fix.php" target="_blank">
            <div class="card-icon" style="color:#3b82f6"><i class="fas fa-tools"></i></div>
            <div class="card-title">MAC Toplu Düzeltme</div>
            <div class="card-desc">Açık MAC uyuşmazlığı alarmlarını listeler ve toplu onaylamayı sağlar.</div>
            <span class="card-badge badge-blue"><i class="fas fa-external-link-alt"></i> Aç</span>
        </a>

    </div>

    <hr class="divider">

    <!-- ── 100 Mbps ve Altı Portlar ──────────────────────────────── -->
    <div class="section-title">
        <i class="fas fa-tachometer-alt"></i> 100 Mbps ve Altında Çalışan UP Portlar
    </div>

    <!-- Stats -->
    <div class="stats-bar">
        <div class="stat-card <?= $portCnt > 0 ? 'warn' : 'info' ?>">
            <div class="num"><?= $portCnt ?></div>
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
        <div class="stat-card <?= $cnt10 > 0 ? 'danger' : 'info' ?>">
            <div class="num"><?= $cnt10 ?></div>
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
            <option value="">Tüm VLAN'lar</option>
            <?php foreach (array_keys($vlanList) as $vlanId): ?>
                <option value="<?= $vlanId ?>"><?= $vlanId ?></option>
            <?php endforeach; ?>
        </select>
        <button class="btn btn-secondary" onclick="location.reload()">
            <i class="fas fa-sync-alt"></i> Yenile
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
                    <th onclick="sortTable(4)">Alias <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(5)">Bağlantı <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(6)">Durum <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(7)">Son Güncelleme <span class="sort-icon fas fa-sort"></span></th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <?php foreach ($ports as $row):
                    $bps          = (int)$row['port_speed'];
                    $speedStr     = formatSpeed($bps);
                    $speedGroupKey = (int)round($bps / 1_000_000) . ' Mbps';
                    $speedClass   = ($bps <= 10_000_000) ? 'speed-10' : 'speed-warn';
                    $ts = !empty($row['poll_timestamp'])
                        ? date('d.m.Y H:i', strtotime($row['poll_timestamp']))
                        : '-';
                    $connDevice = trim($row['conn_device'] ?? '');
                    $connIp     = trim($row['conn_ip']     ?? '');
                    if ($connDevice !== '' && $connIp !== '') {
                        $connHtml = htmlspecialchars($connDevice) . '<br><span style="color:var(--text-light);font-size:11px">' . htmlspecialchars($connIp) . '</span>';
                    } elseif ($connDevice !== '') {
                        $connHtml = htmlspecialchars($connDevice);
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
                    <td style="color:var(--text-light);font-size:12px"><?= htmlspecialchars($row['alias'] ?? '-') ?></td>
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

</div><!-- /container -->

<script>
// ── Filter ──────────────────────────────────────────────────────────────────
function filterTable() {
    const q          = document.getElementById('searchInput').value.toLowerCase();
    const swFilter   = document.getElementById('switchFilter').value;
    const spFilter   = document.getElementById('speedFilter').value;
    const vlanFilter = document.getElementById('vlanFilter').value;
    const rows       = document.querySelectorAll('#tableBody tr');
    let visible = 0;

    rows.forEach(tr => {
        const text      = tr.textContent.toLowerCase();
        const rowSwitch = tr.dataset.switch || '';
        const rowSpeed  = tr.dataset.speed  || '';
        const rowVlan   = tr.dataset.vlan   || '';

        const matchQ    = !q          || text.includes(q);
        const matchSw   = !swFilter   || rowSwitch === swFilter;
        const matchSp   = !spFilter   || rowSpeed  === spFilter;
        const matchVlan = !vlanFilter || rowVlan   === vlanFilter;

        const show = matchQ && matchSw && matchSp && matchVlan;
        tr.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    const rc = document.getElementById('rowCount');
    if (rc) rc.innerHTML = `<strong>${visible}</strong> kayıt gösteriliyor.`;
}

// ── Sort ────────────────────────────────────────────────────────────────────
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
        // Hız sütunu için sayısal sıralama (bps parse)
        if (col === 2) {
            const pa = parseSpeed(va), pb = parseSpeed(vb);
            return asc ? pa - pb : pb - pa;
        }
        const na = parseFloat(va), nb = parseFloat(vb);
        const cmp = (!isNaN(na) && !isNaN(nb)) ? na - nb : va.localeCompare(vb, 'tr');
        return asc ? cmp : -cmp;
    });
    rows.forEach(r => tbody.appendChild(r));

    document.querySelectorAll('thead th').forEach((th, i) => {
        th.classList.toggle('sorted', i === col);
        const icon = th.querySelector('.sort-icon');
        if (icon) {
            icon.className = 'sort-icon fas ' +
                (i !== col ? 'fa-sort' : asc ? 'fa-sort-up' : 'fa-sort-down');
        }
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

// ── Excel Export (SheetJS) ──────────────────────────────────────────────────
function exportXLSX() {
    const headers = ['Switch Adı','Port','Hız','VLAN','Alias','Bağlantı','Durum','Son Güncelleme'];
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
