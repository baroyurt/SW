<?php
/**
 * vlan_alias_check.php — VLAN / Alias Uyumsuzluk Kontrolü
 *
 * Her port için SNMP'den okunan VLAN ID ile port alias'ını kıyaslar.
 * VLAN'a karşılık gelen beklenen tip ile alias örtüşmüyorsa listeler.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();
session_write_close();

header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// VLAN ID → beklenen alias tipi haritası (getData.php ile senkronize)
$vlanTypeMap = [
    30   => 'GUEST',
    40   => 'VIP',
    50   => 'DEVICE',
    70   => 'AP',
    80   => 'KAMERA',
    110  => 'SES',
    120  => 'OTOMASYON',
    130  => 'IPTV',
    140  => 'SANTRAL',
    150  => 'JACKPOT',
    254  => 'SERVER',
    1500 => 'DRGT',
];

/**
 * Alias'ın hangi VLAN tipine ait olduğunu tespit eder.
 *
 * Eşleşme kuralları (öncelik sırası):
 *  1. Tam eşleşme          : "AP"   → AP
 *  2. Başlangıç + ayraç    : "AP-1" → AP
 *  3. Bütün kelime olarak  : "KAT AP FLOOR" → AP
 *  4. Normalize (boşluk/tire/_ kaldırılınca) eşit: "IP TV" → IPTV
 *  5. Normalize alias, normalize tipi içeriyor    : "ULAS BEY DRGT" → DRGT
 *
 * @param  string   $alias
 * @param  string[] $typeList  Bilinen tip adları listesi
 * @return string|null  Eşleşen tip adı ya da null
 */
function detectAliasType(string $alias, array $typeList): ?string {
    $alias     = strtoupper(trim($alias));
    $aliasNorm = preg_replace('/[\s\-_]+/', '', $alias);

    foreach ($typeList as $type) {
        $t     = strtoupper($type);
        $tNorm = preg_replace('/[\s\-_]+/', '', $t);

        // 1. Tam eşleşme
        if ($alias === $t) return $type;

        // 2. Alias başı: TIP + ayraç
        if (preg_match('/^' . preg_quote($t, '/') . '(?:[\s\-_]|$)/', $alias)) return $type;

        // 3. Alias içinde tam kelime olarak
        if (preg_match('/(?:^|[\s\-_])' . preg_quote($t, '/') . '(?:[\s\-_]|$)/', $alias)) return $type;

        // 4. Normalize eşitlik (örn. "IP TV" = "IPTV")
        if ($aliasNorm === $tNorm) return $type;

        // 5. Normalize alias, normalize tipi içeriyor (en az 3 karakter)
        if (strlen($tNorm) >= 3 && str_contains($aliasNorm, $tNorm)) return $type;
    }

    return null;
}

// Tüm VLAN ID'lerini IN listesine dönüştür
$vlanIds = implode(',', array_keys($vlanTypeMap));

$sql = "
    SELECT
        sd.name        AS switch_name,
        sd.ip_address  AS switch_ip,
        psd.port_number,
        psd.vlan_id,
        psd.port_alias AS alias,
        psd.oper_status,
        psd.poll_timestamp
    FROM port_status_data psd
    JOIN snmp_devices sd ON sd.id = psd.device_id
    WHERE psd.vlan_id IN ($vlanIds)
      AND psd.port_alias IS NOT NULL
      AND LTRIM(RTRIM(psd.port_alias)) <> ''
    ORDER BY sd.name, psd.port_number
";

$result = $conn->query($sql);
$allRows = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];

// Bilinen tip listesi
$typeList = array_values($vlanTypeMap);

/**
 * Uyumsuzluk tespiti — YENİ MANTIK:
 *
 * Alias herhangi bir VLAN tipine eşleşiyorsa VE bu tip portun gerçek
 * VLAN tipiyle FARKLI ise → uyumsuz.
 *
 * Alias hiçbir tiple eşleşmiyorsa (açıklayıcı isim, cihaz adı vb.)
 * → uyumsuz sayılmaz.
 *
 * Böylece şunlar artık yanlış çıkmaz:
 *   • "ULAS BEY DRGT"  →  içinde DRGT var, port zaten DRGT VLAN'ında
 *   • "IP TV"          →  normalize → IPTV, port IPTV VLAN'ında
 *   • "CASINO GIRIS LED" / "UPS"  →  hiçbir tiple eşleşmiyor
 */
$mismatches = [];
foreach ($allRows as $row) {
    $vlanId       = (int)$row['vlan_id'];
    $alias        = trim($row['alias']);
    $expectedType = $vlanTypeMap[$vlanId] ?? null;
    if ($expectedType === null) continue;

    $detectedType = detectAliasType($alias, $typeList);

    // Sadece farklı bir tiple eşleşiyorsa uyumsuz say
    if ($detectedType !== null && strtoupper($detectedType) !== strtoupper($expectedType)) {
        $row['expected_type'] = $expectedType;
        $row['detected_type'] = strtoupper($detectedType);
        $mismatches[] = $row;
    }
}

// İstatistikler
$totalScanned  = count($allRows);
$mismatchCount = count($mismatches);

// VLAN bazında gruplama (özet bar için)
$vlanGroups = [];
foreach ($mismatches as $row) {
    $key = $row['vlan_id'] . ' → ' . $row['expected_type'];
    $vlanGroups[$key] = ($vlanGroups[$key] ?? 0) + 1;
}
arsort($vlanGroups);
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VLAN / Alias Uyumsuzluk Kontrolü</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
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
        .header-icon {
            font-size: 36px;
            color: var(--warning);
            flex-shrink: 0;
        }
        .header h1 { color: var(--primary); font-size: 24px; margin-bottom: 6px; }
        .header p  { color: var(--text-light); font-size: 13px; line-height: 1.5; }

        /* ── Stats ── */
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
        .stat-card.ok   .num { color: var(--success); }
        .stat-card.bad  .num { color: var(--danger); }
        .stat-card.info .num { color: var(--primary); }

        /* ── VLAN summary chips ── */
        .vlan-summary {
            background: var(--dark-light);
            padding: 16px 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }
        .vlan-summary .title {
            font-size: 12px;
            color: var(--text-light);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-right: 6px;
            flex-shrink: 0;
        }
        .chip {
            background: #2d1f07;
            border: 1px solid var(--warning);
            color: var(--warning);
            border-radius: 20px;
            padding: 4px 12px;
            font-size: 12px;
            font-weight: 600;
        }

        /* ── Toolbar ── */
        .toolbar {
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .search-box {
            position: relative;
            flex: 1;
            min-width: 220px;
        }
        .search-box i {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-light);
            font-size: 13px;
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
        tbody tr {
            border-bottom: 1px solid #1e2a3a;
            transition: background 0.15s;
        }
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
        .badge-expected {
            background: #0d2b1a;
            color: #4ade80;
            border: 1px solid #16a34a;
        }
        .badge-actual {
            background: #2b0d0d;
            color: #f87171;
            border: 1px solid #b91c1c;
        }
        .badge-vlan {
            background: #0f1f3a;
            color: #93c5fd;
            border: 1px solid #1d4ed8;
        }
        .badge-up   { background:#0d2b1a; color:#4ade80; border:1px solid #16a34a; }
        .badge-down { background:#2b0d0d; color:#f87171; border:1px solid #b91c1c; }

        .mismatch-icon { color: var(--danger); margin-right: 6px; }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-light);
        }
        .empty-state i { font-size: 48px; color: var(--success); margin-bottom: 16px; display: block; }
        .empty-state h2 { font-size: 20px; color: var(--success); margin-bottom: 8px; }

        .row-count {
            font-size: 12px;
            color: var(--text-light);
            padding: 8px 16px;
            border-top: 1px solid var(--border);
        }
        @media (max-width: 768px) {
            .stats-bar { grid-template-columns: repeat(2,1fr); }
            tbody td:nth-child(4),
            tbody td:nth-child(4) { display: none; } /* hide IP on small screens */
        }
    </style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="header">
        <div class="header-icon"><i class="fas fa-exclamation-triangle"></i></div>
        <div>
            <h1>VLAN / Alias Uyumsuzluk Kontrolü</h1>
            <p>
                Her portun SNMP'den okunan VLAN ID'sine göre beklenen alias tipi hesaplanır.<br>
                Alias <strong>başka bir VLAN tipini</strong> işaret ediyorsa uyumsuz olarak listelenir.
                Alias'ta cihaz adı, açıklama gibi keyword olmayan değerler uyumsuz sayılmaz.
                &nbsp;·&nbsp; Son tarama: <strong><?= date('d.m.Y H:i:s') ?></strong>
            </p>
        </div>
    </div>

    <!-- Stats -->
    <div class="stats-bar">
        <div class="stat-card info">
            <div class="num"><?= $totalScanned ?></div>
            <div class="label">Taranan Port</div>
        </div>
        <div class="stat-card bad">
            <div class="num"><?= $mismatchCount ?></div>
            <div class="label">Uyumsuz Port</div>
        </div>
        <div class="stat-card ok">
            <div class="num"><?= max(0, $totalScanned - $mismatchCount) ?></div>
            <div class="label">Uyumlu Port</div>
        </div>
        <div class="stat-card info">
            <div class="num"><?= count($vlanGroups) ?></div>
            <div class="label">Farklı VLAN Grubu</div>
        </div>
    </div>

    <?php if (!empty($vlanGroups)): ?>
    <!-- VLAN summary chips -->
    <div class="vlan-summary">
        <span class="title"><i class="fas fa-layer-group"></i>&nbsp; Gruplama</span>
        <?php foreach ($vlanGroups as $label => $cnt): ?>
            <span class="chip"><?= htmlspecialchars($label) ?> &nbsp;<strong><?= $cnt ?></strong></span>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <!-- Toolbar -->
    <div class="toolbar">
        <div class="search-box">
            <i class="fas fa-search"></i>
            <input type="text" id="searchInput" placeholder="Switch, port, alias veya VLAN ara…" oninput="filterTable()">
        </div>
        <select class="filter-select" id="vlanFilter" onchange="filterTable()">
            <option value="">Tüm VLAN'lar</option>
            <?php
            $uniqueVlans = array_unique(array_column($mismatches, 'vlan_id'));
            sort($uniqueVlans);
            foreach ($uniqueVlans as $v):
                $exp = $vlanTypeMap[$v] ?? '?';
            ?>
                <option value="<?= $v ?>"><?= $v ?> (<?= htmlspecialchars($exp) ?>)</option>
            <?php endforeach; ?>
        </select>
        <select class="filter-select" id="statusFilter" onchange="filterTable()">
            <option value="">Tüm Durumlar</option>
            <option value="up">UP</option>
            <option value="down">DOWN</option>
        </select>
        <button class="btn btn-secondary" onclick="location.reload()">
            <i class="fas fa-sync-alt"></i> Yenile
        </button>
        <button class="btn btn-secondary" onclick="exportCSV()">
            <i class="fas fa-file-csv"></i> CSV
        </button>
    </div>

    <!-- Table -->
    <div class="table-wrap">
        <?php if (empty($mismatches)): ?>
            <div class="empty-state">
                <i class="fas fa-check-circle"></i>
                <h2>Uyumsuzluk Yok!</h2>
                <p>Tüm port alias'ları VLAN tiplerine uyuyor.</p>
            </div>
        <?php else: ?>
        <table id="mismatchTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Switch Adı <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(1)">IP Adresi <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(2)">Port <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(3)">VLAN ID <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(4)">VLAN Tipi <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(5)">Alias Tipi <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(6)">Mevcut Alias <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(7)">Durum <span class="sort-icon fas fa-sort"></span></th>
                    <th onclick="sortTable(8)">Son Güncelleme <span class="sort-icon fas fa-sort"></span></th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <?php foreach ($mismatches as $row):
                    $ts = !empty($row['poll_timestamp'])
                        ? date('d.m.Y H:i', strtotime($row['poll_timestamp']))
                        : '-';
                    $statusClass = ($row['oper_status'] === 'up') ? 'badge-up' : 'badge-down';
                    $statusLabel = strtoupper($row['oper_status'] ?? 'unknown');
                ?>
                <tr>
                    <td><?= htmlspecialchars($row['switch_name'] ?? '-') ?></td>
                    <td><?= htmlspecialchars($row['switch_ip'] ?? '-') ?></td>
                    <td><?= (int)$row['port_number'] ?></td>
                    <td><span class="badge badge-vlan"><?= (int)$row['vlan_id'] ?></span></td>
                    <td><span class="badge badge-expected"><?= htmlspecialchars($row['expected_type']) ?></span></td>
                    <td>
                        <i class="fas fa-times-circle mismatch-icon"></i>
                        <span class="badge badge-actual"><?= htmlspecialchars($row['detected_type']) ?></span>
                    </td>
                    <td style="color:var(--text-light);font-size:12px"><?= htmlspecialchars($row['alias']) ?></td>
                    <td><span class="badge <?= $statusClass ?>"><?= $statusLabel ?></span></td>
                    <td style="color:var(--text-light)"><?= $ts ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <div class="row-count" id="rowCount">
            Toplam <strong><?= $mismatchCount ?></strong> uyumsuz port gösteriliyor.
        </div>
        <?php endif; ?>
    </div>

</div>

<script>
// ── Filter ──────────────────────────────────────────────────────────
function filterTable() {
    const q      = document.getElementById('searchInput').value.toLowerCase();
    const vlan   = document.getElementById('vlanFilter').value;
    const status = document.getElementById('statusFilter').value.toLowerCase();
    const rows   = document.querySelectorAll('#tableBody tr');
    let visible  = 0;
    rows.forEach(tr => {
        const cells = tr.querySelectorAll('td');
        const text  = tr.textContent.toLowerCase();
        const rowVlan   = cells[3]?.textContent.trim();
        const rowStatus = cells[7]?.textContent.trim().toLowerCase();
        const matchQ      = !q      || text.includes(q);
        const matchVlan   = !vlan   || rowVlan   === vlan;
        const matchStatus = !status || rowStatus === status;
        const show = matchQ && matchVlan && matchStatus;
        tr.style.display = show ? '' : 'none';
        if (show) visible++;
    });
    const rc = document.getElementById('rowCount');
    if (rc) rc.innerHTML = `<strong>${visible}</strong> kayıt gösteriliyor.`;
}

// ── Sort ─────────────────────────────────────────────────────────────
let sortState = { col: -1, asc: true };
function sortTable(col) {
    const tbody = document.getElementById('tableBody');
    if (!tbody) return;
    const rows  = Array.from(tbody.querySelectorAll('tr'));
    const asc   = (sortState.col === col) ? !sortState.asc : true;
    sortState   = { col, asc };

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
        if (icon) {
            icon.className = 'sort-icon fas ' +
                (i !== col ? 'fa-sort' : asc ? 'fa-sort-up' : 'fa-sort-down');
        }
    });
}

// ── CSV Export ────────────────────────────────────────────────────────
function exportCSV() {
    const headers = ['Switch Adı','IP Adresi','Port','VLAN ID','VLAN Tipi','Alias Tipi','Mevcut Alias','Durum','Son Güncelleme'];
    const rows    = Array.from(document.querySelectorAll('#tableBody tr'))
        .filter(r => r.style.display !== 'none')
        .map(r => Array.from(r.querySelectorAll('td'))
            .map(td => '"' + td.textContent.trim().replace(/"/g,'""') + '"'));
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const a   = document.createElement('a');
    a.href    = 'data:text/csv;charset=utf-8,\uFEFF' + encodeURIComponent(csv);
    a.download = 'vlan_alias_uyumsuzluk_' + new Date().toISOString().slice(0,10) + '.csv';
    a.click();
}
</script>
</body>
</html>
