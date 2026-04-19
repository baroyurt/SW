<?php
/**
 * MAC Toplu Düzeltme - Tek seferlik araç
 * Tüm açık MAC uyuşmazlığı alarmlarını listeler ve tek tıkla kapatır.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

$currentUser = $auth->getUser();

header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MAC Toplu Düzeltme</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }

        :root {
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #0f172a;
            --dark-light: #1e293b;
            --card: #1e293b;
            --border: #334155;
            --text: #e2e8f0;
            --text-light: #94a3b8;
        }

        body {
            background: linear-gradient(135deg, var(--dark) 0%, var(--dark-light) 100%);
            color: var(--text);
            min-height: 100vh;
            padding: 24px;
        }

        .container { max-width: 1300px; margin: 0 auto; }

        /* ── Header ── */
        .page-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 24px;
        }
        .page-header h1 {
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .page-header h1 .icon { color: var(--warning); }
        .badge-count {
            background: var(--danger);
            color: #fff;
            border-radius: 99px;
            padding: 2px 10px;
            font-size: 0.85rem;
            font-weight: 700;
        }

        /* ── Toolbar ── */
        .toolbar {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }

        /* ── Buttons ── */
        .btn {
            padding: 8px 18px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 7px;
            transition: opacity .15s, transform .1s;
        }
        .btn:active { transform: scale(.97); }
        .btn:disabled { opacity: .5; cursor: not-allowed; }
        .btn-primary  { background: var(--primary);  color: #fff; }
        .btn-primary:hover:not(:disabled)  { background: var(--primary-dark); }
        .btn-success  { background: var(--success);  color: #fff; }
        .btn-success:hover:not(:disabled)  { opacity: .85; }
        .btn-warning  { background: var(--warning);  color: #fff; }
        .btn-warning:hover:not(:disabled)  { opacity: .85; }
        .btn-secondary { background: var(--border); color: var(--text); }
        .btn-secondary:hover:not(:disabled) { opacity: .85; }

        /* ── Summary cards ── */
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px 20px;
            text-align: center;
        }
        .stat-card .value {
            font-size: 2rem;
            font-weight: 800;
            line-height: 1;
        }
        .stat-card .label { font-size: .8rem; color: var(--text-light); margin-top: 4px; }
        .stat-card.total  .value { color: var(--primary); }
        .stat-card.ok     .value { color: var(--success); }
        .stat-card.warn   .value { color: var(--warning); }
        .stat-card.fail   .value { color: var(--danger); }

        /* ── Table ── */
        .table-wrapper {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
        }
        thead th {
            background: #0f172a;
            padding: 11px 14px;
            text-align: left;
            color: var(--text-light);
            font-weight: 600;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        tbody tr {
            border-bottom: 1px solid var(--border);
            transition: background .12s;
        }
        tbody tr:last-child { border-bottom: none; }
        tbody tr:hover { background: rgba(59,130,246,.06); }
        tbody td { padding: 10px 14px; vertical-align: middle; }

        .mono { font-family: monospace; letter-spacing: .03em; }
        .tag-mac-new  { color: var(--success); font-weight: 700; }
        .tag-mac-old  { color: var(--text-light); text-decoration: line-through; }

        .badge-severity {
            padding: 2px 8px;
            border-radius: 6px;
            font-size: .75rem;
            font-weight: 700;
        }
        .sev-HIGH     { background: rgba(239,68,68,.2);   color: #ef4444; }
        .sev-CRITICAL { background: rgba(239,68,68,.35);  color: #ff6b6b; }
        .sev-MEDIUM   { background: rgba(245,158,11,.2);  color: #f59e0b; }
        .sev-LOW      { background: rgba(100,116,139,.2); color: #94a3b8; }

        /* Row result overlays */
        .row-ok   { background: rgba(16,185,129,.08) !important; }
        .row-warn { background: rgba(245,158,11,.08) !important; }
        .row-fail { background: rgba(239,68,68,.08) !important; }
        .result-badge {
            font-size: .78rem;
            padding: 2px 8px;
            border-radius: 6px;
            font-weight: 600;
        }
        .result-ok   { background: rgba(16,185,129,.2);  color: var(--success); }
        .result-warn { background: rgba(245,158,11,.2);  color: var(--warning); }
        .result-fail { background: rgba(239,68,68,.2);   color: var(--danger); }

        /* ── Spinner ── */
        .spinner {
            display: none;
            width: 18px; height: 18px;
            border: 3px solid rgba(255,255,255,.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin .6s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* ── Toast ── */
        #toastContainer {
            position: fixed;
            bottom: 24px; right: 24px;
            display: flex; flex-direction: column; gap: 8px;
            z-index: 9999;
        }
        .toast {
            background: rgba(30,41,59,.97);
            border-left: 4px solid var(--primary);
            padding: 12px 18px;
            border-radius: 10px;
            font-size: .9rem;
            max-width: 420px;
            word-break: break-word;
            animation: slideIn .25s ease;
        }
        .toast.success { border-color: var(--success); }
        .toast.error   { border-color: var(--danger); }
        .toast.warning { border-color: var(--warning); }
        @keyframes slideIn {
            from { transform: translateX(80px); opacity: 0; }
            to   { transform: translateX(0);    opacity: 1; }
        }

        /* ── Empty state ── */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-light);
        }
        .empty-state i { font-size: 3rem; margin-bottom: 16px; display: block; color: var(--success); }
        .empty-state h2 { font-size: 1.2rem; margin-bottom: 8px; color: var(--text); }

        /* ── Filter ── */
        .search-box {
            background: rgba(255,255,255,.05);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 7px 12px;
            color: var(--text);
            font-size: .9rem;
            outline: none;
            width: 220px;
        }
        .search-box:focus { border-color: var(--primary); }
        .search-box::placeholder { color: var(--text-light); }

        .cb { width: 16px; height: 16px; accent-color: var(--primary); cursor: pointer; }
    </style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="page-header">
        <h1>
            <span class="icon"><i class="fas fa-wrench"></i></span>
            MAC Toplu Düzeltme
            <span class="badge-count" id="totalBadge">…</span>
        </h1>
        <a href="port_alarms.php" class="btn btn-secondary">
            <i class="fas fa-arrow-left"></i> Alarm Sayfası
        </a>
    </div>

    <!-- Summary stats -->
    <div class="summary" id="summaryCards" style="display:none;">
        <div class="stat-card total">
            <div class="value" id="statTotal">0</div>
            <div class="label">Toplam Alarm</div>
        </div>
        <div class="stat-card ok">
            <div class="value" id="statOk">0</div>
            <div class="label">Başarılı</div>
        </div>
        <div class="stat-card warn">
            <div class="value" id="statWarn">0</div>
            <div class="label">Alarm Kapandı<br>(port güncellenemedi)</div>
        </div>
        <div class="stat-card fail">
            <div class="value" id="statFail">0</div>
            <div class="label">Hata</div>
        </div>
    </div>

    <!-- Toolbar -->
    <div class="toolbar">
        <button class="btn btn-success" id="btnFix" disabled onclick="fixSelected()">
            <span class="spinner" id="spinner"></span>
            <i class="fas fa-check-double" id="btnFixIcon"></i>
            Seçilenleri Kaydet ve Kapat
        </button>
        <button class="btn btn-secondary" onclick="refresh()">
            <i class="fas fa-sync-alt"></i> Yenile
        </button>
        <input type="search" class="search-box" id="searchBox" placeholder="Switch veya MAC ara…" oninput="filterTable()">
        <span id="selCount" style="color:var(--text-light);font-size:.88rem;"></span>
    </div>

    <!-- Table -->
    <div class="table-wrapper" id="tableWrapper">
        <div class="empty-state"><i class="fas fa-circle-notch fa-spin"></i><h2>Yükleniyor…</h2></div>
    </div>

</div>

<div id="toastContainer"></div>

<script>
    let alarmData = [];     // raw alarm rows from API
    let resultMap = {};     // alarmId → result after fix

    // ── Load alarms ─────────────────────────────────────────────────────────
    async function loadAlarms() {
        document.getElementById('tableWrapper').innerHTML =
            '<div class="empty-state"><i class="fas fa-circle-notch fa-spin"></i><h2>Yükleniyor…</h2></div>';
        document.getElementById('totalBadge').textContent = '…';
        document.getElementById('btnFix').disabled = true;
        resultMap = {};

        try {
            const resp = await fetch('../api/port_change_api.php?action=get_mac_mismatch_alarms');
            const data = await resp.json();
            if (!data.success) throw new Error(data.error || 'API hatası');
            alarmData = data.alarms || [];
        } catch (e) {
            document.getElementById('tableWrapper').innerHTML =
                `<div class="empty-state"><i class="fas fa-exclamation-triangle" style="color:var(--danger)"></i><h2>Yüklenemedi: ${escHtml(e.message)}</h2></div>`;
            return;
        }

        document.getElementById('totalBadge').textContent = alarmData.length;
        renderTable();
        updateSelCount();
    }

    // ── Render table ────────────────────────────────────────────────────────
    function renderTable() {
        if (alarmData.length === 0) {
            document.getElementById('tableWrapper').innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-check-circle"></i>
                    <h2>Açık MAC uyuşmazlığı alarmı yok</h2>
                    <p>Tüm portlar kayıtlı MAC adresleriyle eşleşiyor.</p>
                </div>`;
            document.getElementById('btnFix').disabled = true;
            return;
        }

        const q = document.getElementById('searchBox').value.toLowerCase();
        const rows = alarmData.filter(a => {
            if (!q) return true;
            return (a.device_name || '').toLowerCase().includes(q)
                || (a.device_ip  || '').toLowerCase().includes(q)
                || (a.mac_address || '').toLowerCase().includes(q)
                || (a.old_value  || '').toLowerCase().includes(q)
                || (a.new_value  || '').toLowerCase().includes(q);
        });

        if (rows.length === 0) {
            document.getElementById('tableWrapper').innerHTML =
                '<div class="empty-state"><i class="fas fa-search"></i><h2>Sonuç bulunamadı</h2></div>';
            return;
        }

        let html = `<table>
            <thead><tr>
                <th><input type="checkbox" class="cb" id="cbAll" onchange="toggleAll(this.checked)" title="Tümünü seç/kaldır"></th>
                <th>Switch</th>
                <th>Port</th>
                <th>Önceki MAC (Beklenen)</th>
                <th>Mevcut MAC (Kayıt edilecek)</th>
                <th>Tip</th>
                <th>Önem</th>
                <th>Tekrar</th>
                <th>Son Görülme</th>
                <th>Sonuç</th>
            </tr></thead>
            <tbody>`;

        rows.forEach(a => {
            const res = resultMap[a.id];

            let rowCls, resBadge;
            if (!res) {
                rowCls   = '';
                resBadge = '—';
            } else if (!res.success) {
                rowCls   = 'row-fail';
                resBadge = `<span class="result-badge result-fail">❌ ${escHtml(res.error || `Alarm #${res.alarm_id} işlenemedi`)}</span>`;
            } else if (res.port_rows_updated === 0) {
                rowCls   = 'row-warn';
                resBadge = `<span class="result-badge result-warn">⚠️ Alarm kapandı (port güncellenemedi)</span>`;
            } else {
                rowCls   = 'row-ok';
                resBadge = `<span class="result-badge result-ok">✅ Kaydedildi</span>`;
            }

            const currentMac = a.mac_address || a.new_value || '?';
            const oldMac     = a.old_value || '?';
            const lastSeen   = (a.last_occurrence || '').replace('T', ' ').substring(0, 16);
            const sevCls     = 'sev-' + (a.severity || 'LOW');
            const typeTxt    = a.alarm_type === 'mac_moved' ? 'MAC Taşındı' : 'MAC Uyuşmazlığı';

            html += `<tr class="${rowCls}" data-id="${a.id}" data-name="${escAttr(a.device_name)}" data-ip="${escAttr(a.device_ip)}" data-curmac="${escAttr(currentMac)}" data-oldmac="${escAttr(oldMac)}">
                <td><input type="checkbox" class="cb row-cb" data-id="${a.id}"
                    data-mac="${escAttr(currentMac)}"
                    data-device="${a.device_id}"
                    data-port="${a.port_number}"
                    ${res && res.success ? 'disabled' : ''}
                    onchange="updateSelCount()"></td>
                <td>
                    <span style="font-weight:600">${escHtml(a.device_name || '—')}</span><br>
                    <span style="color:var(--text-light);font-size:.8rem">${escHtml(a.device_ip || '')}</span>
                </td>
                <td style="font-weight:700;font-size:1.05rem">Port ${escHtml(String(a.port_number))}</td>
                <td class="mono tag-mac-old">${escHtml(oldMac)}</td>
                <td class="mono tag-mac-new">${escHtml(currentMac)}</td>
                <td style="color:var(--text-light);font-size:.82rem">${escHtml(typeTxt)}</td>
                <td><span class="badge-severity ${sevCls}">${escHtml(a.severity || '')}</span></td>
                <td style="text-align:center">${escHtml(String(a.occurrence_count || 1))}</td>
                <td style="color:var(--text-light);font-size:.82rem;white-space:nowrap">${escHtml(lastSeen)}</td>
                <td>${resBadge}</td>
            </tr>`;
        });

        html += '</tbody></table>';
        document.getElementById('tableWrapper').innerHTML = html;

        // Auto-check all unfixed rows
        document.querySelectorAll('.row-cb:not(:disabled)').forEach(cb => cb.checked = true);
        updateSelCount();
    }

    function filterTable() { renderTable(); updateSelCount(); }

    // ── Select helpers ───────────────────────────────────────────────────────
    function toggleAll(checked) {
        document.querySelectorAll('.row-cb:not(:disabled)').forEach(cb => cb.checked = checked);
        updateSelCount();
    }

    function updateSelCount() {
        const total    = document.querySelectorAll('.row-cb:not(:disabled)').length;
        const selected = document.querySelectorAll('.row-cb:not(:disabled):checked').length;
        const btnFix   = document.getElementById('btnFix');
        btnFix.disabled = selected === 0;
        const el = document.getElementById('selCount');
        el.textContent = total > 0 ? `${selected} / ${total} seçili` : '';

        const cbAll = document.getElementById('cbAll');
        if (cbAll) cbAll.checked = total > 0 && selected === total;
    }

    // ── Fix selected ─────────────────────────────────────────────────────────
    async function fixSelected() {
        const checked = document.querySelectorAll('.row-cb:not(:disabled):checked');
        if (!checked.length) { showToast('Hiç satır seçilmedi', 'warning'); return; }

        const items = Array.from(checked).map(cb => ({
            alarm_id:    parseInt(cb.dataset.id),
            mac_address: cb.dataset.mac,
            device_id:   parseInt(cb.dataset.device),
            port_number: parseInt(cb.dataset.port),
        }));

        // UI: spinner on
        const btnFix    = document.getElementById('btnFix');
        const spinner   = document.getElementById('spinner');
        const btnIcon   = document.getElementById('btnFixIcon');
        btnFix.disabled = true;
        spinner.style.display = 'inline-block';
        btnIcon.style.display = 'none';

        try {
            const resp = await fetch('../api/port_change_api.php?action=bulk_mac_fix', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ items }),
            });
            const data = await resp.json();

            if (!data.results) throw new Error(data.error || 'API yanıt hatası');

            // Merge results into resultMap
            let ok = 0, warn = 0, fail = 0;
            data.results.forEach(r => {
                resultMap[r.alarm_id] = r;
                if (r.success) {
                    if (r.port_rows_updated === 0) warn++; else ok++;
                } else {
                    fail++;
                }
            });

            // Show summary cards
            document.getElementById('summaryCards').style.display = '';
            document.getElementById('statTotal').textContent = data.total;
            document.getElementById('statOk').textContent   = ok;
            document.getElementById('statWarn').textContent  = warn;
            document.getElementById('statFail').textContent  = fail;

            renderTable();
            updateSelCount();

            if (fail === 0 && warn === 0) {
                showToast(`✅ ${ok} alarm başarıyla kapatıldı ve ports.mac güncellendi.`, 'success', 6000);
            } else if (fail === 0) {
                showToast(`⚠️ ${ok} kayıt tamam, ${warn} alarmda ports.mac güncellenemedi (whitelist üzerinden otomatik düzelecek).`, 'warning', 8000);
            } else {
                showToast(`${ok} başarılı, ${warn} uyarı, ${fail} hata. Sayfayı yenileyin.`, 'error', 8000);
            }

        } catch (e) {
            showToast('Hata: ' + e.message, 'error');
        } finally {
            spinner.style.display = 'none';
            btnIcon.style.display = 'inline';
        }
    }

    function refresh() { loadAlarms(); }

    // ── Toast ────────────────────────────────────────────────────────────────
    function showToast(msg, type = 'info', duration = 5000) {
        const el = document.createElement('div');
        el.className = `toast ${type}`;
        el.textContent = msg;
        document.getElementById('toastContainer').appendChild(el);
        setTimeout(() => el.remove(), duration);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    function escHtml(s) {
        return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    function escAttr(s) {
        return String(s ?? '').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    // ── Init ─────────────────────────────────────────────────────────────────
    loadAlarms();
</script>
</body>
</html>
