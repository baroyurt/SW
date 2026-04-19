<?php
/**
 * matris.php — Alarm Matrisi
 *
 * Sistemin tüm alarm koşullarını, tetiklenme mantığını ve
 * aktif/tarihsel istatistikleri tek sayfada gösterir.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();
// Release PHP session lock immediately – this page only reads session data.
session_write_close();

$currentUser = $auth->getUser();

header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

/* ------------------------------------------------------------------ */
/* Read SNMP Worker config.yml to get live system settings             */
/* ------------------------------------------------------------------ */
$pollInterval         = 15;   // default
$parallelDevices      = 15;
$snmpStaggerMs        = 0;
$dbMaxWorkers         = 0;
$pollingDataInterval  = 0;
$macPollInterval      = 0;
$deviceInfoPollInterval = 0;
$portPollInterval     = 0;
$unreachableThreshold = 3;
$vlanExclude          = [];
$emailEnabled         = false;
$emailSmtpHost        = '';
$emailSmtpPort        = 465;
$emailUser            = '';
$emailFrom            = '';
$emailToList          = [];
$notifyOn             = [];
$telegramEnabled      = false;
$telegramNotifyOn     = [];
$severityRouting      = [];  // [severity => ['telegram'=>bool,'email'=>bool,'events'=>[...]]]
$triggerOn            = [];  // global trigger_on list

$configYml = __DIR__ . '/../snmp_worker/config/config.yml';
if (file_exists($configYml)) {
    $yml = file_get_contents($configYml);
    // Note: using regex instead of a YAML parser to avoid requiring an extra
    // PHP package (symfony/yaml).  The config.yml uses a predictable fixed
    // format written by admin_snmp_config.php, so simple regex is reliable.

    // polling block
    if (preg_match('/^polling:\s*\n((?:[ \t]+[^\n]*\n)*)/m', $yml, $pb)) {
        $pBlock = $pb[1];
        if (preg_match('/interval:\s*(\d+)/m',              $pBlock, $m)) $pollInterval           = (int)$m[1];
        if (preg_match('/parallel_devices:\s*(\d+)/m',      $pBlock, $m)) $parallelDevices        = (int)$m[1];
        if (preg_match('/snmp_stagger_ms:\s*(\d+)/m',       $pBlock, $m)) $snmpStaggerMs          = (int)$m[1];
        if (preg_match('/db_max_workers:\s*(\d+)/m',        $pBlock, $m)) $dbMaxWorkers           = (int)$m[1];
        if (preg_match('/polling_data_interval:\s*(\d+)/m', $pBlock, $m)) $pollingDataInterval    = (int)$m[1];
        if (preg_match('/mac_poll_interval:\s*(\d+)/m',     $pBlock, $m)) $macPollInterval        = (int)$m[1];
        if (preg_match('/device_info_poll_interval:\s*(\d+)/m',$pBlock,$m)) $deviceInfoPollInterval = (int)$m[1];
        if (preg_match('/port_poll_interval:\s*(\d+)/m',    $pBlock, $m)) $portPollInterval       = (int)$m[1];
    }

    // alarms block — unreachable_threshold, trigger_on, vlan_exclude, severity_routing
    if (preg_match('/^alarms:\s*\n((?:[ \t]+[^\n]*\n)*)/m', $yml, $ab)) {
        $aBlock = $ab[1];
        if (preg_match('/unreachable_threshold:\s*(\d+)/m', $aBlock, $m)) $unreachableThreshold = (int)$m[1];

        // trigger_on list
        if (preg_match('/trigger_on:((?:\s*\n(?:[ \t]+-[^\n]*\n))+)/m', $aBlock, $trig)) {
            preg_match_all('/- ([^\n#]+)/', $trig[1], $trm);
            $triggerOn = array_filter(array_map('trim', $trm[1] ?? []));
        }

        // vlan_exclude list
        if (preg_match('/vlan_exclude:((?:\s*\n(?:[ \t]+-[^\n]*\n))+)/m', $aBlock, $vex)) {
            preg_match_all('/- (\d+)/', $vex[1], $vem);
            $vlanExclude = array_map('intval', $vem[1] ?? []);
        }

        // severity_routing — parse each severity level block
        if (preg_match('/severity_routing:\s*\n((?:[ \t]+[^\n]*\n)*)/m', $yml, $sr)) {
            $srBlock = $sr[1];
            foreach (['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as $sv) {
                if (preg_match('/' . $sv . ':\s*\n((?:[ \t]{4,}[^\n]*\n)+)/m', $srBlock, $svb)) {
                    $svBlock = $svb[1];
                    $tg = preg_match('/telegram:\s*true/i', $svBlock) === 1;
                    $em = preg_match('/email:\s*true/i',    $svBlock) === 1;
                    $evts = [];
                    if (preg_match('/events:((?:\s*\n(?:[ \t]+-[^\n]*\n))+)/m', $svBlock, $evb)) {
                        preg_match_all('/- ([^\n#]+)/', $evb[1], $evm);
                        $evts = array_filter(array_map('trim', $evm[1] ?? []));
                    }
                    $severityRouting[$sv] = ['telegram' => $tg, 'email' => $em, 'events' => array_values($evts)];
                }
            }
        }
    }

    // email block
    if (preg_match('/^email:\s*\n((?:[ \t]+[^\n]*\n)*)/m', $yml, $em)) {
        $block = $em[1];
        $emailEnabled  = preg_match('/enabled:\s*true/i', $block) === 1;
        if (preg_match('/smtp_host:\s*"?([^"\n]+)"?/', $block, $hm))  $emailSmtpHost = trim($hm[1], '" ');
        if (preg_match('/smtp_port:\s*(\d+)/',          $block, $pm))  $emailSmtpPort = (int)$pm[1];
        if (preg_match('/smtp_user:\s*"?([^"\n]+)"?/',  $block, $um))  $emailUser     = trim($um[1], '" ');
        if (preg_match('/from_address:\s*"?([^"\n]+)"?/', $block, $fm)) $emailFrom    = trim($fm[1], '" ');
        // to_addresses list (scoped to email block to avoid false matches)
        if (preg_match('/to_addresses:((?:\s*\n(?:[ \t]+-[^\n]*\n))+)/m', $block, $tma)) {
            preg_match_all('/- "?([^"\n#]+)"?/', $tma[1], $tos);
            $emailToList = array_filter(array_map('trim', $tos[1] ?? []));
        }
        // email notify_on (scoped to email block)
        if (preg_match('/notify_on:((?:\s*\n(?:[ \t]+-[^\n]*\n))+)/m', $block, $noa)) {
            preg_match_all('/- ([^\n#]+)/', $noa[1], $nos);
            $notifyOn = array_filter(array_map('trim', $nos[1] ?? []));
        }
    }

    // telegram block
    if (preg_match('/^telegram:\s*\n((?:[ \t]+[^\n]*\n)*)/m', $yml, $tgb)) {
        $tgBlock = $tgb[1];
        $telegramEnabled = preg_match('/enabled:\s*true/i', $tgBlock) === 1;
        if (preg_match('/notify_on:((?:\s*\n(?:[ \t]+-[^\n]*\n))+)/m', $tgBlock, $tnoa)) {
            preg_match_all('/- ([^\n#]+)/', $tnoa[1], $tnos);
            $telegramNotifyOn = array_filter(array_map('trim', $tnos[1] ?? []));
        }
    }
}

/* ------------------------------------------------------------------ */
/* Live statistics from DB                                             */
/* ------------------------------------------------------------------ */
function qInt($conn, $sql) {
    $r = $conn->query($sql);
    if (!$r) return 0;
    $row = $r->fetch_row();
    return (int)($row[0] ?? 0);
}

$stats = [
    'active_alarms'        => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE'"),
    'acknowledged_alarms'  => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACKNOWLEDGED'"),
    'mac_added_active'     => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE' AND alarm_type='mac_added'"),
    'mac_moved_active'     => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE' AND alarm_type='mac_moved'"),
    'vlan_changed_active'  => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE' AND alarm_type='vlan_changed'"),
    'description_changed_active' => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE' AND alarm_type='description_changed'"),
    'port_down_active'     => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE' AND alarm_type='port_down'"),
    'device_unreachable_active' => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE' AND alarm_type='device_unreachable'"),
    'core_link_down_active'=> qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE' AND alarm_type='core_link_down'"),
    'port_up_active'       => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE' AND alarm_type='port_up'"),
    'total_alarm_history'  => qInt($conn, "SELECT COUNT(*) FROM alarms"),
    'suppressed'           => qInt($conn, "SELECT COUNT(*) FROM alarms WHERE status='ACTIVE' AND silence_until > NOW()"),
    'total_mac_tracking'   => qInt($conn, "SELECT COUNT(*) FROM mac_address_tracking"),
    'total_changes_today'  => qInt($conn, "SELECT COUNT(*) FROM port_change_history WHERE CAST(change_timestamp AS DATE)=CAST(GETDATE() AS DATE)"),
    'total_switches'       => qInt($conn, "SELECT COUNT(*) FROM snmp_devices"),
    'switches_online'      => qInt($conn, "SELECT COUNT(*) FROM snmp_devices WHERE status='ONLINE'"),
    'switches_offline'     => qInt($conn, "SELECT COUNT(*) FROM snmp_devices WHERE status IN ('OFFLINE','UNREACHABLE','ERROR')"),
    'registered_devices'   => qInt($conn, "SELECT COUNT(*) FROM mac_device_registry WHERE device_name IS NOT NULL AND device_name != ''"),
];

/* Last poll timestamp per device */
$lastPollRow = $conn->query(
    "SELECT MAX(poll_timestamp) AS last_poll, COUNT(DISTINCT device_id) AS polled_devices
     FROM port_status_data WHERE poll_timestamp > DATE_SUB(NOW(), INTERVAL 5 MINUTE)"
);
$lastPoll = $lastPollRow ? $lastPollRow->fetch_assoc() : ['last_poll' => null, 'polled_devices' => 0];

/* Device status breakdown */
$deviceStatusRows = [];
$dsRes = $conn->query(
    "SELECT d.id, d.name, d.ip_address, d.status, d.poll_failures,
            MAX(p.poll_timestamp) AS last_poll_ts
     FROM snmp_devices d
     LEFT JOIN device_polling_data p ON p.device_id = d.id
     GROUP BY d.id, d.name, d.ip_address, d.status, d.poll_failures
     ORDER BY FIELD(d.status,'UNREACHABLE','ERROR','OFFLINE','ONLINE'), d.name"
);
if ($dsRes) {
    while ($drow = $dsRes->fetch_assoc()) $deviceStatusRows[] = $drow;
}

/* Alarm severity breakdown (active only) */
$severityBreakdown = [];
$svRes = $conn->query(
    "SELECT severity, COUNT(*) as cnt FROM alarms WHERE status='ACTIVE' GROUP BY severity ORDER BY FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW','INFO')"
);
if ($svRes) {
    while ($sr = $svRes->fetch_assoc()) $severityBreakdown[$sr['severity']] = (int)$sr['cnt'];
}

/* Recent alarm activity (last 30) — enriched with more fields */
$recentAlarms = [];
$sql = "SELECT a.id, a.alarm_type, a.severity, a.title, a.message,
               a.port_number, a.mac_address, a.old_value, a.new_value,
               a.first_occurrence, a.last_occurrence, a.occurrence_count,
               a.acknowledged_at, a.acknowledged_by, a.silence_until,
               d.name AS device_name, d.ip_address AS device_ip
        FROM alarms a
        LEFT JOIN snmp_devices d ON a.device_id = d.id
        WHERE a.status = 'ACTIVE'
        ORDER BY
            CASE a.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
            a.last_occurrence DESC
        LIMIT 30";
$res = $conn->query($sql);
if ($res) {
    while ($row = $res->fetch_assoc()) $recentAlarms[] = $row;
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alarm Matrisi — CHAMADA NETWORK MANAGER</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        html { zoom: 0.9; }
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }

        :root {
            --primary:      #3b82f6;
            --primary-dark: #2563eb;
            --secondary:    #8b5cf6;
            --success:      #10b981;
            --warning:      #f59e0b;
            --danger:       #ef4444;
            --dark:         #0f172a;
            --dark-light:   #1e293b;
            --card:         #1e293b;
            --card2:        #0f172a;
            --text:         #e2e8f0;
            --text-light:   #94a3b8;
            --border:       #334155;
        }

        body {
            background: linear-gradient(135deg, var(--dark) 0%, var(--dark-light) 100%);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
        }

        a { color: var(--primary); text-decoration: none; }
        a:hover { text-decoration: underline; }

        /* ---- Layout ---- */
        .container { max-width: 1400px; margin: 0 auto; }

        /* ---- Header ---- */
        .page-header {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px 32px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
        }
        .page-header h1 {
            font-size: 26px;
            font-weight: 700;
            color: var(--text);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .page-header h1 i { color: var(--primary); }
        .page-header p { color: var(--text-light); font-size: 14px; margin-top: 6px; }
        .nav-back {
            background: rgba(59,130,246,.15);
            border: 1px solid rgba(59,130,246,.35);
            border-radius: 10px;
            padding: 10px 18px;
            color: var(--primary);
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: background .2s;
            cursor: pointer;
            text-decoration: none;
        }
        .nav-back:hover { background: rgba(59,130,246,.25); text-decoration: none; }

        /* ---- Stat cards ---- */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 14px;
            margin-bottom: 28px;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px 20px;
            text-align: center;
        }
        .stat-card .val {
            font-size: 32px;
            font-weight: 700;
            line-height: 1.1;
        }
        .stat-card .lbl {
            font-size: 11px;
            color: var(--text-light);
            text-transform: uppercase;
            letter-spacing: .5px;
            margin-top: 6px;
        }
        .stat-card.red   .val { color: var(--danger); }
        .stat-card.orange .val { color: var(--warning); }
        .stat-card.blue  .val { color: var(--primary); }
        .stat-card.green .val { color: var(--success); }
        .stat-card.purple .val { color: var(--secondary); }

        /* ---- Section ---- */
        .section {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 26px 28px;
            margin-bottom: 24px;
        }
        .section-title {
            font-size: 17px;
            font-weight: 700;
            color: var(--text);
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .section-title i { color: var(--primary); }

        /* ---- Matrix table ---- */
        .matrix-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13.5px;
        }
        .matrix-table th {
            background: var(--card2);
            color: var(--text-light);
            text-transform: uppercase;
            letter-spacing: .5px;
            font-size: 11px;
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        .matrix-table td {
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }
        .matrix-table tr:last-child td { border-bottom: none; }
        .matrix-table tr:hover td { background: rgba(59,130,246,.04); }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            white-space: nowrap;
        }
        .badge-success  { background: rgba(16,185,129,.15); color: var(--success);   border: 1px solid rgba(16,185,129,.3); }
        .badge-danger   { background: rgba(239, 68,68,.15); color: var(--danger);    border: 1px solid rgba(239,68,68,.3); }
        .badge-warning  { background: rgba(245,158,11,.15); color: var(--warning);   border: 1px solid rgba(245,158,11,.3); }
        .badge-primary  { background: rgba(59,130,246,.15); color: var(--primary);   border: 1px solid rgba(59,130,246,.3); }
        .badge-secondary{ background: rgba(139, 92,246,.15); color: var(--secondary); border: 1px solid rgba(139,92,246,.3); }
        .badge-neutral  { background: rgba(148,163,184,.1);  color: var(--text-light); border: 1px solid var(--border); }

        .check-yes  { color: var(--success); font-size: 15px; }
        .check-no   { color: var(--danger);  font-size: 15px; }

        /* ---- Alarm type legend ---- */
        .type-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
            gap: 16px;
            margin-top: 8px;
        }
        .type-card {
            background: var(--card2);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px 20px;
        }
        .type-card h4 {
            font-size: 14px;
            font-weight: 700;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .type-card p  { font-size: 13px; color: var(--text-light); line-height: 1.6; }
        .type-card ul { margin: 6px 0 0 16px; font-size: 13px; color: var(--text-light); }
        .type-card ul li { margin-bottom: 3px; }

        /* ---- Recent alarms table ---- */
        .severity-CRITICAL { color: #f87171; font-weight: 700; }
        .severity-HIGH     { color: #fb923c; font-weight: 700; }
        .severity-MEDIUM   { color: var(--warning); }
        .severity-LOW      { color: var(--success); }
        .severity-INFO     { color: var(--text-light); }

        /* ---- Flow diagram ---- */
        .flow {
            display: flex;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 0;
            margin-top: 10px;
        }
        .flow-step {
            background: var(--card2);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 12px 16px;
            font-size: 13px;
            min-width: 170px;
            text-align: center;
        }
        .flow-step strong { display: block; margin-bottom: 4px; color: var(--text); }
        .flow-step span   { color: var(--text-light); font-size: 12px; }
        .flow-arrow {
            align-self: center;
            padding: 0 8px;
            color: var(--text-light);
            font-size: 20px;
        }

        /* ---- Suppression rules ---- */
        .supp-rule {
            background: var(--card2);
            border-left: 3px solid var(--primary);
            border-radius: 0 8px 8px 0;
            padding: 12px 16px;
            margin-bottom: 12px;
            font-size: 13px;
        }
        .supp-rule strong { color: var(--text); display: block; margin-bottom: 4px; }
        .supp-rule span   { color: var(--text-light); }

        /* ---- Responsive ---- */
        @media (max-width: 768px) {
            .page-header { flex-direction: column; align-items: flex-start; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .matrix-table { font-size: 12px; }
            .type-grid { grid-template-columns: 1fr; }
        }

        /* ---- Print ---- */
        @media print {
            body { background: white; color: black; }
            .nav-back { display: none; }
        }
    </style>
</head>
<body>
<div class="container">

    <!-- ================================================================ -->
    <!-- Header                                                            -->
    <!-- ================================================================ -->
    <div class="page-header">
        <div>
            <h1><i class="fas fa-table"></i> Alarm Matrisi</h1>
            <p>Sistemin tüm alarm koşulları, tetiklenme mantığı ve aktif istatistikler &mdash;
               Güncellenme: <strong><?php echo date('d.m.Y H:i:s'); ?></strong>
               &mdash; <i class="fas fa-clock"></i> Tarama aralığı: <strong><?php echo $pollInterval; ?> saniye</strong></p>
        </div>
        <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
            <a href="../index.php" class="nav-back"><i class="fas fa-home"></i> Dashboard</a>
            <a href="port_alarms.php" class="nav-back" style="color:var(--warning); border-color:rgba(245,158,11,.35); background:rgba(245,158,11,.1);">
                <i class="fas fa-bell"></i> Aktif Alarmlar
            </a>
            <button onclick="location.reload()" class="nav-back" style="color:var(--success); border-color:rgba(16,185,129,.35); background:rgba(16,185,129,.1);">
                <i class="fas fa-sync-alt"></i> Yenile
            </button>
        </div>
    </div>

    <!-- ================================================================ -->
    <!-- System Configuration Card                                         -->
    <!-- ================================================================ -->
    <div class="section" style="padding:20px 24px;">
        <div class="section-title" style="justify-content:space-between;flex-wrap:wrap;gap:8px;">
            <span><i class="fas fa-cogs"></i> Sistem Yapılandırması</span>
            <a href="admin_snmp_config.php#snmp" target="_parent"
               style="font-size:12px;background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.35);border-radius:8px;padding:5px 12px;color:var(--primary);text-decoration:none;display:flex;align-items:center;gap:5px;">
                <i class="fas fa-edit"></i> Sorgu Süresini Değiştir
            </a>
        </div>

        <?php if ($pollInterval > 120): ?>
        <div style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.35);border-left:4px solid var(--danger);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px;color:#fca5a5;">
            <i class="fas fa-exclamation-triangle" style="color:var(--danger);margin-right:6px;"></i>
            <strong>Yüksek Tarama Aralığı:</strong> <?php echo $pollInterval; ?>s — Alarm gecikmesi <?php echo $pollInterval; ?> saniyeye kadar çıkabilir.
            <a href="admin_snmp_config.php#snmp" target="_parent" style="color:var(--danger);margin-left:6px;">Değiştir →</a>
        </div>
        <?php elseif ($pollInterval < 30): ?>
        <div style="background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.35);border-left:4px solid var(--warning);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px;color:#fde68a;">
            <i class="fas fa-bolt" style="color:var(--warning);margin-right:6px;"></i>
            <strong>Düşük Tarama Aralığı:</strong> <?php echo $pollInterval; ?>s — SW ve Server üzerinde yüksek CPU yükü oluşabilir.
        </div>
        <?php endif; ?>

        <div style="display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:16px;">

            <!-- Polling -->
            <div style="background:var(--card2);border:1px solid var(--border);border-radius:12px;padding:16px 18px;">
                <div style="font-size:12px;color:var(--text-light);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;">
                    <i class="fas fa-clock" style="color:var(--primary);"></i> Tarama (Polling)
                </div>
                <div style="display:flex;flex-direction:column;gap:5px;font-size:13px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span style="color:var(--text-light);">Tarama aralığı</span>
                        <span style="display:flex;align-items:center;gap:6px;">
                            <strong style="color:<?php echo ($pollInterval >= 30 && $pollInterval <= 120) ? 'var(--success)' : 'var(--warning)'; ?>;">
                                <?php echo $pollInterval; ?> s
                            </strong>
                            <?php if ($pollInterval === 60): ?>
                            <span class="badge" style="background:rgba(16,185,129,.2);color:var(--success);font-size:10px;padding:2px 6px;border-radius:4px;">Önerilen</span>
                            <?php elseif ($pollInterval < 30): ?>
                            <span class="badge" style="background:rgba(245,158,11,.2);color:var(--warning);font-size:10px;padding:2px 6px;border-radius:4px;">Yüksek Yük</span>
                            <?php elseif ($pollInterval > 120): ?>
                            <span class="badge" style="background:rgba(239,68,68,.2);color:var(--danger);font-size:10px;padding:2px 6px;border-radius:4px;">Yavaş Alarm</span>
                            <?php endif; ?>
                        </span>
                    </div>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">Paralel cihaz</span>
                        <strong style="color:var(--primary);"><?php echo $parallelDevices; ?></strong>
                    </div>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">İzlenen switch</span>
                        <strong style="color:var(--primary);"><?php echo $stats['total_switches']; ?></strong>
                    </div>
                    <?php if ($portPollInterval > 0): ?>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">Port poll aralığı</span>
                        <strong style="color:var(--text-light);"><?php echo $portPollInterval; ?> s</strong>
                    </div>
                    <?php endif; ?>
                    <?php if ($macPollInterval > 0): ?>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">MAC poll aralığı</span>
                        <strong style="color:var(--text-light);"><?php echo $macPollInterval; ?> s</strong>
                    </div>
                    <?php endif; ?>
                    <?php if ($deviceInfoPollInterval > 0): ?>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">Cihaz bilgisi poll</span>
                        <strong style="color:var(--text-light);"><?php echo $deviceInfoPollInterval; ?> s</strong>
                    </div>
                    <?php endif; ?>
                    <?php if ($snmpStaggerMs > 0): ?>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">SNMP stagger</span>
                        <strong style="color:var(--text-light);"><?php echo $snmpStaggerMs; ?> ms</strong>
                    </div>
                    <?php endif; ?>
                    <?php if ($dbMaxWorkers > 0): ?>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">DB yazma işçisi</span>
                        <strong style="color:var(--text-light);"><?php echo $dbMaxWorkers; ?></strong>
                    </div>
                    <?php endif; ?>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">Erişilemez eşiği</span>
                        <strong style="color:var(--warning);"><?php echo $unreachableThreshold; ?> başarısız poll</strong>
                    </div>
                    <?php if ($lastPoll['last_poll']): ?>
                    <div style="border-top:1px solid var(--border);margin-top:4px;padding-top:4px;display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">Son tarama</span>
                        <strong style="color:var(--text);font-size:12px;"><?php echo date('H:i:s', strtotime($lastPoll['last_poll'])); ?></strong>
                    </div>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">Aktif cihaz (5 dk)</span>
                        <strong style="color:var(--success);"><?php echo (int)$lastPoll['polled_devices']; ?></strong>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($vlanExclude)): ?>
                    <div style="border-top:1px solid var(--border);margin-top:4px;padding-top:4px;">
                        <div style="color:var(--text-light);margin-bottom:3px;">VLAN dışlama:</div>
                        <div style="display:flex;flex-wrap:wrap;gap:4px;">
                            <?php foreach ($vlanExclude as $vl): ?>
                            <span class="badge badge-neutral" style="font-size:11px;">VLAN <?php echo (int)$vl; ?></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            <div style="background:var(--card2);border:1px solid var(--border);border-radius:12px;padding:16px 18px;">
                <div style="font-size:12px;color:var(--text-light);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;">
                    <i class="fas fa-envelope" style="color:<?php echo $emailEnabled ? 'var(--success)' : 'var(--danger)'; ?>;"></i>
                    E-posta Bildirimleri
                    <span class="badge <?php echo $emailEnabled ? 'badge-success' : 'badge-danger'; ?>" style="margin-left:6px;font-size:10px;">
                        <?php echo $emailEnabled ? 'AKTİF' : 'KAPALI'; ?>
                    </span>
                </div>
                <div style="display:flex;flex-direction:column;gap:5px;font-size:13px;">
                    <?php if ($emailEnabled): ?>
                    <div style="display:flex;justify-content:space-between;gap:8px;">
                        <span style="color:var(--text-light);white-space:nowrap;">SMTP</span>
                        <strong style="color:var(--text);font-size:12px;text-align:right;"><?php echo htmlspecialchars($emailSmtpHost); ?>:<?php echo $emailSmtpPort; ?></strong>
                    </div>
                    <div style="display:flex;justify-content:space-between;gap:8px;">
                        <span style="color:var(--text-light);white-space:nowrap;">Gönderen</span>
                        <strong style="color:var(--text);font-size:12px;text-align:right;"><?php echo htmlspecialchars($emailFrom ?: $emailUser); ?></strong>
                    </div>
                    <?php foreach ($emailToList as $toAddr): ?>
                    <div style="display:flex;justify-content:space-between;gap:8px;">
                        <span style="color:var(--text-light);white-space:nowrap;">Alıcı</span>
                        <strong style="color:var(--primary);font-size:12px;text-align:right;"><?php echo htmlspecialchars($toAddr); ?></strong>
                    </div>
                    <?php endforeach; ?>
                    <?php if (!empty($notifyOn)): ?>
                    <div style="border-top:1px solid var(--border);margin-top:4px;padding-top:4px;">
                        <div style="color:var(--text-light);font-size:11px;margin-bottom:3px;">notify_on (ek liste):</div>
                        <div style="display:flex;flex-wrap:wrap;gap:3px;">
                            <?php foreach ($notifyOn as $no): ?>
                            <span class="badge badge-neutral" style="font-size:10px;"><?php echo htmlspecialchars($no); ?></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                    <?php else: ?>
                    <div style="color:var(--text-light);font-size:12px;">E-posta bildirimleri devre dışı.
                        <a href="admin_snmp_config.php" style="color:var(--primary);">Yapılandır →</a>
                    </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Telegram -->
            <div style="background:var(--card2);border:1px solid var(--border);border-radius:12px;padding:16px 18px;">
                <div style="font-size:12px;color:var(--text-light);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;">
                    <i class="fab fa-telegram" style="color:<?php echo $telegramEnabled ? '#229ED9' : 'var(--danger)'; ?>;"></i>
                    Telegram Bildirimleri
                    <span class="badge <?php echo $telegramEnabled ? 'badge-primary' : 'badge-danger'; ?>" style="margin-left:6px;font-size:10px;">
                        <?php echo $telegramEnabled ? 'AKTİF' : 'KAPALI'; ?>
                    </span>
                </div>
                <div style="font-size:13px;color:var(--text-light);">
                    <?php if ($telegramEnabled): ?>
                    Telegram bildirimleri aktif.
                    <?php if (!empty($telegramNotifyOn)): ?>
                    <div style="margin-top:6px;">
                        <div style="font-size:11px;margin-bottom:3px;">notify_on:</div>
                        <div style="display:flex;flex-wrap:wrap;gap:3px;">
                            <?php foreach ($telegramNotifyOn as $tn): ?>
                            <span class="badge badge-primary" style="font-size:10px;"><?php echo htmlspecialchars($tn); ?></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php else: ?>
                    <div style="margin-top:6px;font-size:11px;color:var(--text-light);">notify_on: [] (yönlendirme severity_routing'den)</div>
                    <?php endif; ?>
                    <?php else: ?>
                    Telegram bildirimleri devre dışı.
                    <a href="admin_snmp_config.php" style="color:var(--primary);">Yapılandır →</a>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Registry -->
            <div style="background:var(--card2);border:1px solid var(--border);border-radius:12px;padding:16px 18px;">
                <div style="font-size:12px;color:var(--text-light);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;">
                    <i class="fas fa-address-book" style="color:var(--secondary);"></i> Cihaz Kaydı
                </div>
                <div style="display:flex;flex-direction:column;gap:5px;font-size:13px;">
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">Kayıtlı cihaz</span>
                        <strong style="color:var(--primary);"><?php echo $stats['registered_devices']; ?></strong>
                    </div>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">Takip edilen MAC</span>
                        <strong style="color:var(--primary);"><?php echo $stats['total_mac_tracking']; ?></strong>
                    </div>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:var(--text-light);">Bugünkü değişim</span>
                        <strong style="color:var(--warning);"><?php echo $stats['total_changes_today']; ?></strong>
                    </div>
                </div>
            </div>
        </div>

        <!-- Severity Routing Table -->
        <?php if (!empty($severityRouting)): ?>
        <div style="margin-top:16px;">
            <div style="font-size:12px;color:var(--text-light);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;">
                <i class="fas fa-route" style="color:var(--primary);"></i> Alarm Bildirim Yönlendirmesi (severity_routing)
            </div>
            <div style="overflow-x:auto;">
            <table class="matrix-table" style="font-size:12.5px;">
                <thead>
                    <tr>
                        <th>Şiddet</th>
                        <th><i class="fas fa-envelope"></i> E-posta</th>
                        <th><i class="fab fa-telegram"></i> Telegram</th>
                        <th>Kapsanan Alarm Türleri</th>
                    </tr>
                </thead>
                <tbody>
                <?php
                $svColors = ['CRITICAL'=>'badge-danger','HIGH'=>'badge-warning','MEDIUM'=>'badge-primary','LOW'=>'badge-neutral','INFO'=>'badge-secondary'];
                foreach ($severityRouting as $sv => $cfg):
                    $svBadge = $svColors[$sv] ?? 'badge-neutral';
                ?>
                <tr>
                    <td><span class="badge <?php echo $svBadge; ?>"><?php echo $sv; ?></span></td>
                    <td>
                        <?php if ($cfg['email']): ?>
                            <span class="check-yes"><i class="fas fa-check-circle"></i></span>
                        <?php else: ?>
                            <span class="check-no"><i class="fas fa-times-circle"></i></span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if ($cfg['telegram']): ?>
                            <span style="color:#229ED9;"><i class="fas fa-check-circle"></i></span>
                        <?php else: ?>
                            <span class="check-no"><i class="fas fa-times-circle"></i></span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <div style="display:flex;flex-wrap:wrap;gap:4px;">
                        <?php foreach ($cfg['events'] as $ev): ?>
                            <span class="badge badge-neutral" style="font-size:11px;"><?php echo htmlspecialchars($ev); ?></span>
                        <?php endforeach; ?>
                        <?php if (empty($cfg['events'])): ?>
                            <span style="color:var(--text-light);font-size:11px;">—</span>
                        <?php endif; ?>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- ================================================================ -->
    <!-- Live Statistics                                                    -->
    <!-- ================================================================ -->
    <div class="stats-grid">
        <div class="stat-card red">
            <div class="val"><?php echo $stats['active_alarms']; ?></div>
            <div class="lbl"><i class="fas fa-bell"></i> Aktif Alarm</div>
        </div>
        <div class="stat-card orange">
            <div class="val"><?php echo $stats['acknowledged_alarms']; ?></div>
            <div class="lbl"><i class="fas fa-check"></i> Onaylandı</div>
        </div>
        <div class="stat-card orange">
            <div class="val"><?php echo $stats['mac_added_active']; ?></div>
            <div class="lbl"><i class="fas fa-plus-circle"></i> MAC Eklendi</div>
        </div>
        <div class="stat-card orange">
            <div class="val"><?php echo $stats['mac_moved_active']; ?></div>
            <div class="lbl"><i class="fas fa-random"></i> MAC Taşındı</div>
        </div>
        <div class="stat-card blue">
            <div class="val"><?php echo $stats['vlan_changed_active']; ?></div>
            <div class="lbl"><i class="fas fa-project-diagram"></i> VLAN Değişti</div>
        </div>
        <div class="stat-card blue">
            <div class="val"><?php echo $stats['description_changed_active']; ?></div>
            <div class="lbl"><i class="fas fa-tag"></i> Açıklama Değişti</div>
        </div>
        <div class="stat-card red">
            <div class="val"><?php echo $stats['port_down_active']; ?></div>
            <div class="lbl"><i class="fas fa-ethernet"></i> Port Kapandı</div>
        </div>
        <div class="stat-card red">
            <div class="val"><?php echo $stats['device_unreachable_active']; ?></div>
            <div class="lbl"><i class="fas fa-server"></i> Cihaz Erişilemez</div>
        </div>
        <div class="stat-card red">
            <div class="val"><?php echo $stats['core_link_down_active']; ?></div>
            <div class="lbl"><i class="fas fa-network-wired"></i> Core Uplink Kesildi</div>
        </div>
        <div class="stat-card purple">
            <div class="val"><?php echo $stats['suppressed']; ?></div>
            <div class="lbl"><i class="fas fa-volume-mute"></i> Sessizde</div>
        </div>
        <div class="stat-card green">
            <div class="val"><?php echo $stats['switches_online']; ?>/<?php echo $stats['total_switches']; ?></div>
            <div class="lbl"><i class="fas fa-server"></i> Switch Online</div>
        </div>
        <div class="stat-card <?php echo $stats['switches_offline'] > 0 ? 'red' : 'green'; ?>">
            <div class="val"><?php echo $stats['switches_offline']; ?></div>
            <div class="lbl"><i class="fas fa-exclamation-triangle"></i> Switch Çevrimdışı</div>
        </div>
        <div class="stat-card green">
            <div class="val"><?php echo $stats['total_mac_tracking']; ?></div>
            <div class="lbl"><i class="fas fa-database"></i> Takip Edilen MAC</div>
        </div>
        <div class="stat-card green">
            <div class="val"><?php echo $stats['total_changes_today']; ?></div>
            <div class="lbl"><i class="fas fa-calendar-day"></i> Bugünkü Değişim</div>
        </div>
    </div>

    <!-- ================================================================ -->
    <!-- Alarm Severity Breakdown                                           -->
    <!-- ================================================================ -->
    <?php if (!empty($severityBreakdown)): ?>
    <div class="section" style="padding:18px 24px;">
        <div class="section-title"><i class="fas fa-layer-group"></i> Aktif Alarm Şiddet Dağılımı</div>
        <div style="display:flex; gap:12px; flex-wrap:wrap;">
            <?php
            $svColors = ['CRITICAL'=>'#f87171','HIGH'=>'#fb923c','MEDIUM'=>'#f59e0b','LOW'=>'#10b981','INFO'=>'#94a3b8'];
            foreach (['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as $sv):
                $cnt = $severityBreakdown[$sv] ?? 0;
                if ($cnt === 0) continue;
                $col = $svColors[$sv];
            ?>
            <div style="background:var(--card2);border:1px solid var(--border);border-radius:10px;padding:12px 20px;text-align:center;min-width:100px;">
                <div style="font-size:26px;font-weight:700;color:<?php echo $col; ?>;"><?php echo $cnt; ?></div>
                <div style="font-size:11px;color:var(--text-light);text-transform:uppercase;margin-top:4px;"><?php echo $sv; ?></div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- ================================================================ -->
    <!-- Device Status Panel                                               -->
    <!-- ================================================================ -->
    <?php if (!empty($deviceStatusRows)): ?>
    <div class="section">
        <div class="section-title"><i class="fas fa-server"></i> Cihaz Durum Paneli
            <span style="font-size:12px;font-weight:400;color:var(--text-light);">(tüm switch'ler)</span>
        </div>
        <div style="overflow-x:auto;">
        <table class="matrix-table">
            <thead>
                <tr>
                    <th>Cihaz Adı</th>
                    <th>IP Adresi</th>
                    <th>Durum</th>
                    <th>Son Tarama</th>
                    <th>Poll Hatası</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($deviceStatusRows as $ds):
                $stMap = [
                    'ONLINE'      => ['badge-success','check-circle','ONLINE'],
                    'OFFLINE'     => ['badge-neutral','minus-circle','OFFLINE'],
                    'UNREACHABLE' => ['badge-danger','times-circle','ERİŞİLEMEZ'],
                    'ERROR'       => ['badge-warning','exclamation-circle','HATA'],
                ];
                $st = strtoupper($ds['status'] ?? 'OFFLINE');
                [$sc,$si,$sl] = $stMap[$st] ?? ['badge-neutral','question-circle',$st];
            ?>
            <tr>
                <td><strong><?php echo htmlspecialchars($ds['name'] ?? '—'); ?></strong></td>
                <td style="font-family:monospace;font-size:13px;"><?php echo htmlspecialchars($ds['ip_address'] ?? '—'); ?></td>
                <td><span class="badge <?php echo $sc; ?>"><i class="fas fa-<?php echo $si; ?>"></i> <?php echo $sl; ?></span></td>
                <td style="font-size:12px;color:var(--text-light);">
                    <?php echo $ds['last_poll_ts'] ? date('d.m.Y H:i:s', strtotime($ds['last_poll_ts'])) : '—'; ?>
                </td>
                <td>
                    <?php $pf = (int)($ds['poll_failures'] ?? 0); ?>
                    <?php if ($pf > 0): ?>
                        <span style="color:var(--danger);font-weight:700;"><?php echo $pf; ?></span>
                    <?php else: ?>
                        <span style="color:var(--success);">0</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>
    <?php endif; ?>

    <!-- ================================================================ -->
    <!-- MAC Alarm Matrix (main table)                                     -->
    <!-- ================================================================ -->
    <div class="section">
        <div class="section-title"><i class="fas fa-table"></i> MAC Alarm Matrisi — Port Boşaltma Senaryoları</div>
        <table class="matrix-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Senaryo</th>
                    <th>Port Tablosu (ports.mac)</th>
                    <th>Önceki SNMP Snapshot</th>
                    <th>MAC Tracking Kaydı</th>
                    <th>Beklenen Davranış</th>
                    <th>Alarm?</th>
                    <th>Durum</th>
                </tr>
            </thead>
            <tbody>
                <!-- Row 1 -->
                <tr>
                    <td>1</td>
                    <td>
                        <strong>Port boşa çekildi, cihaz fiziksel olarak aynı yerde</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">UI'dan MAC kaydı silindi (boşa çek butonu). Cihaz portta takılı kalmaya devam etti.</span>
                    </td>
                    <td><span class="badge badge-neutral">Boş (silindi)</span></td>
                    <td><span class="badge badge-success">Aynı MAC mevcut</span></td>
                    <td><span class="badge badge-primary">Herhangi bir port</span></td>
                    <td>MAC zaten biliniyordu → Alarm <strong>OLMAMALI</strong></td>
                    <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span></td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Düzeltildi</span></td>
                </tr>
                <!-- Row 2 -->
                <tr>
                    <td>2</td>
                    <td>
                        <strong>Port boşa çekildi, cihaz kısa süre çevrimdışı oldu, geri bağlandı (aynı MAC)</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">UI'dan MAC silindi. Cihaz çıkarıldı → SNMP boş snapshot aldı → Cihaz tekrar takıldı, aynı MAC döndü.</span><br>
                        <span style="color:var(--warning); font-size:12px;"><i class="fas fa-info-circle"></i> MAC, Device Import'ta (mac_device_registry) kayıtlıysa alarm YOK. Kayıtlı değilse <strong>mac_added</strong> alarmı oluşur — kaydedilmesi için.</span>
                    </td>
                    <td><span class="badge badge-neutral">Boş (silindi)</span></td>
                    <td><span class="badge badge-neutral">Boş (cihaz çıkarılmıştı)</span></td>
                    <td><span class="badge badge-success">Önceki port kaydı var (previous_device/port eşleşiyor)</span></td>
                    <td>
                        MAC Device Import'ta kayıtlı → Alarm <strong>OLMAMALI</strong><br>
                        MAC Device Import'ta <strong>kayıtsız</strong> → <span style="color:var(--warning);">mac_added Alarm <strong>OLMALI</strong></span>
                    </td>
                    <td>
                        <span class="check-no"><i class="fas fa-times-circle"></i> Kayıtlıysa: Alarm Yok</span><br>
                        <span class="check-yes"><i class="fas fa-check-circle"></i> Kayıtsızsa: Alarm Oluştur</span>
                    </td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Güncellendi</span></td>
                </tr>
                <!-- Row 3 -->
                <tr>
                    <td>3</td>
                    <td>
                        <strong>Port boşa çekildi, FARKLI MAC geldi</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">UI'dan MAC silindi. Farklı bir cihaz porta takıldı.</span><br>
                        <span style="color:var(--warning); font-size:12px;"><i class="fas fa-info-circle"></i>
                          Karar önceliği (B3 kuralı):<br>
                          1. Tracking başka porttan geldiğini gösteriyorsa → <strong>mac_moved</strong><br>
                          2. MAC mac_device_registry'de <strong>kayıtsız</strong> → <strong>mac_added</strong><br>
                          3. MAC mac_device_registry'de kayıtlı → <strong>alarm YOK</strong>, sadece tracking güncellenir
                        </span>
                    </td>
                    <td><span class="badge badge-neutral">Boş (silindi)</span></td>
                    <td><span class="badge badge-warning">Farklı MAC veya boş</span></td>
                    <td><span class="badge badge-danger">Yok veya farklı port kaydı</span></td>
                    <td>
                        Tracking → başka port: <strong>mac_moved</strong><br>
                        Kayıtsız yeni cihaz: <strong>mac_added</strong><br>
                        Kayıtlı bilininen cihaz: Alarm <strong>OLMAMALI</strong>
                    </td>
                    <td>
                        <span class="check-yes"><i class="fas fa-check-circle"></i> Taşındıysa: mac_moved</span><br>
                        <span class="check-yes"><i class="fas fa-check-circle"></i> Yeniyse: mac_added</span><br>
                        <span class="check-no"><i class="fas fa-times-circle"></i> Kayıtlıysa: Alarm Yok</span>
                    </td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Güncellendi</span></td>
                </tr>
                <!-- Row 4 -->
                <tr>
                    <td>4</td>
                    <td>
                        <strong>Hiç bağlanmamış porta yeni MAC geldi</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">Daha önce hiç kayıt yapılmamış bir porta ilk defa cihaz takıldı.</span><br>
                        <span style="color:var(--warning); font-size:12px;"><i class="fas fa-info-circle"></i>
                          MAC mac_device_registry'de <strong>kayıtlıysa</strong> alarm oluşmaz — cihaz zaten envanterde.
                          Kayıtlı değilse <strong>mac_added</strong> alarmı oluşturulur.
                        </span>
                    </td>
                    <td><span class="badge badge-neutral">Boş (hiç girilmedi)</span></td>
                    <td><span class="badge badge-neutral">Boş veya yok</span></td>
                    <td><span class="badge badge-danger">MAC tracking kaydı yok</span></td>
                    <td>
                        mac_device_registry'de kayıtlı → Alarm <strong>OLMAMALI</strong><br>
                        mac_device_registry'de <strong>kayıtsız</strong> → mac_added Alarm <strong>OLMALI</strong>
                    </td>
                    <td>
                        <span class="check-no"><i class="fas fa-times-circle"></i> Kayıtlıysa: Alarm Yok</span><br>
                        <span class="check-yes"><i class="fas fa-check-circle"></i> Kayıtsızsa: mac_added</span>
                    </td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Güncellendi</span></td>
                </tr>
                <!-- Row 5 -->
                <tr>
                    <td>5</td>
                    <td>
                        <strong>Kayıtlı MAC ile SNMP MAC eşleşiyor</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">ports.mac ile SNMP'den okunan MAC aynı → Normal durum.</span>
                    </td>
                    <td><span class="badge badge-success">Kayıtlı MAC var</span></td>
                    <td><span class="badge badge-success">Aynı MAC</span></td>
                    <td><span class="badge badge-primary">Güncellenir</span></td>
                    <td>Beklenen durum → Alarm <strong>OLMAMALI</strong></td>
                    <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span></td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Korundu</span></td>
                </tr>
                <!-- Row 6 -->
                <tr>
                    <td>6</td>
                    <td>
                        <strong>MAC taşındı (port değişti)</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">Bir MAC adresi farklı bir porta veya farklı bir switch'e taşındı.</span>
                    </td>
                    <td><span class="badge badge-warning">Önceki konuma kayıtlı</span></td>
                    <td><span class="badge badge-warning">Farklı port</span></td>
                    <td><span class="badge badge-warning">Farklı device_id / port_number</span></td>
                    <td>Cihaz başka yere taşındı → Alarm <strong>OLMALI</strong></td>
                    <td><span class="check-yes"><i class="fas fa-check-circle"></i> Alarm Oluştur</span></td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Korundu</span></td>
                </tr>
                <!-- Row 7 -->
                <tr>
                    <td>7</td>
                    <td>
                        <strong>İlk tarama — port daha önce hiç görülmemişti</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">Sistem yeni kuruldu veya switch yeni eklendi; snapshot yok.</span>
                    </td>
                    <td><span class="badge badge-neutral">Herhangi biri</span></td>
                    <td><span class="badge badge-danger">Snapshot yok (ilk tarama)</span></td>
                    <td><span class="badge badge-neutral">—</span></td>
                    <td>İlk taramada alarm flood oluşmasın → Alarm <strong>OLMAMALI</strong></td>
                    <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span></td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Korundu</span></td>
                </tr>
                <!-- Row 8 -->
                <tr>
                    <td>8</td>
                    <td>
                        <strong>Hub / Yönetilmeyen switch portu</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">Porta aynı anda birden fazla MAC görülüyor (≥ 2). Bu hub veya yönetilmeyen switch bağlantısıdır.</span>
                    </td>
                    <td><span class="badge badge-neutral">Herhangi biri</span></td>
                    <td><span class="badge badge-primary">Çok MAC</span></td>
                    <td><span class="badge badge-primary">Otomatik kayıt</span></td>
                    <td>Hub portu — MAC değişimi normaldir → Alarm <strong>OLMAMALI</strong></td>
                    <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span></td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Korundu</span></td>
                </tr>
                <!-- Row 9 -->
                <tr>
                    <td>9</td>
                    <td>
                        <strong>AP / Trunk port — istemci MAC rotasyonu</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">ports.mac'te kayıtlı AP MAC'i var. SNMP'de ek istemci MAC'leri görülüyor (wi-fi kullanıcıları).</span>
                    </td>
                    <td><span class="badge badge-success">AP MAC'i kayıtlı</span></td>
                    <td><span class="badge badge-primary">AP + istemci MAC'ler</span></td>
                    <td><span class="badge badge-primary">Sessizce güncellenir</span></td>
                    <td>AP istemcileri normal trafik → Alarm <strong>OLMAMALI</strong></td>
                    <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span></td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Korundu</span></td>
                </tr>
                <!-- Row 10 -->
                <tr>
                    <td>10</td>
                    <td>
                        <strong>Kayıtlı cihaz eksik — farklı MAC var</strong><br>
                        <span style="color:var(--text-light); font-size:12px;">ports.mac'te bir MAC kayıtlı ama SNMP tamamen farklı MAC görüyor (cihaz değiştirilmiş).</span>
                    </td>
                    <td><span class="badge badge-danger">Farklı MAC kayıtlı</span></td>
                    <td><span class="badge badge-danger">Farklı MAC SNMP'de</span></td>
                    <td><span class="badge badge-warning">Farklı cihaz</span></td>
                    <td>Yetkisiz cihaz değişimi → Alarm <strong>OLMALI</strong></td>
                    <td><span class="check-yes"><i class="fas fa-check-circle"></i> Alarm Oluştur</span></td>
                    <td><span class="badge badge-success"><i class="fas fa-check"></i> Korundu</span></td>
                </tr>
            </tbody>
        </table>
    </div>

    <!-- ================================================================ -->
    <!-- All Alarm Types Reference                                          -->
    <!-- ================================================================ -->
    <div class="section">
        <div class="section-title"><i class="fas fa-list-alt"></i> Alarm Türleri — Tam Referans</div>
        <div class="type-grid">

            <div class="type-card">
                <h4><span class="badge badge-danger"><i class="fas fa-plus-circle"></i> mac_added</span></h4>
                <p><strong>Tetiklenme:</strong> Kayıtlı MAC'i olmayan bir porta yeni MAC geldi ve bu MAC daha önce bu portta görülmemişti.</p>
                <ul>
                    <li>Şiddet: <strong>MEDIUM</strong></li>
                    <li>Sessizleştirilebilir: Evet</li>
                    <li>MAC İşle butonu ile kaydedilebilir</li>
                </ul>
            </div>

            <div class="type-card">
                <h4><span class="badge badge-warning"><i class="fas fa-random"></i> mac_moved</span></h4>
                <p><strong>Tetiklenme (2 koşul — herhangi biri):</strong></p>
                <ul>
                    <li><strong>MAC Tracking ile:</strong> Takip edilen bir MAC adresi farklı bir switch portuna veya farklı bir switch'e taşındı (MACAddressTracking tablosunda farklı device_id / port_number)</li>
                    <li><strong>Anlık Snapshot ile:</strong> SNMP snapshotları arasında portun tek MAC'i tamamen değişti — eski MAC gitti, yeni MAC geldi (cihaz değiştirme senaryosu). AP veya çok MAC'li portlarda bu ikinci koşul <strong>tetiklenmez</strong>.</li>
                </ul>
                <p style="margin-top:6px;"><strong>Şiddet:</strong> HIGH &nbsp;|&nbsp; MAC takip tablosunda move_count artar</p>
            </div>

            <div class="type-card">
                <h4><span class="badge badge-primary"><i class="fas fa-project-diagram"></i> vlan_changed</span></h4>
                <p><strong>Tetiklenme:</strong> Portun VLAN ID'si değişti.</p>
                <ul>
                    <li>Şiddet: <strong>MEDIUM</strong></li>
                    <li>Varsayılan VLAN (0/1) → Anlamlı VLAN geçişlerinde tetiklenir</li>
                    <li>AP portları (kayıtlı MAC'i olan): VLAN 70 ↔ WiFi SSID (30/40/50/130/140/254) geçişlerinde <strong>tetiklenmez</strong> (AP SSID rotasyonu)</li>
                    <li>Normal erişim portları (kayıtlı MAC'i olmayan): <span style="color:var(--warning);">her VLAN geçişinde <strong>tetiklenir</strong></span> — VLAN 70 ↔ 130 dahil</li>
                </ul>
            </div>

            <div class="type-card">
                <h4><span class="badge badge-primary"><i class="fas fa-tag"></i> description_changed</span></h4>
                <p><strong>Tetiklenme:</strong> SNMP'den okunan port açıklaması (ifAlias / ifDescr) değişti.</p>
                <ul>
                    <li>Şiddet: <strong>LOW</strong></li>
                    <li>Eski ve yeni açıklama alarmda görünür</li>
                    <li>Boş ↔ Dolu geçişlerde de tetiklenir</li>
                </ul>
            </div>

            <div class="type-card" style="border-color:rgba(139,92,246,.4);">
                <h4><span class="badge badge-secondary"><i class="fas fa-power-off"></i> status_changed</span>
                    <span style="font-size:11px;color:var(--warning);margin-left:8px;"><i class="fas fa-tools"></i> Henüz üretilmiyor</span>
                </h4>
                <p><strong>Tetiklenme:</strong> Portun admin veya operasyonel durumu değişti (up/down/testing).</p>
                <ul>
                    <li>Şiddet: <strong>LOW</strong></li>
                    <li>Yalnızca bağlı port olarak izlenen portlarda</li>
                    <li style="color:var(--warning);"><i class="fas fa-exclamation-triangle"></i> Bu alarm türü Python worker'da henüz implement edilmemiştir; veritabanında bu tipte kayıt görünmez.</li>
                </ul>
            </div>

            <div class="type-card">
                <h4><span class="badge badge-danger"><i class="fas fa-ethernet"></i> port_down</span></h4>
                <p><strong>Tetiklenme:</strong> Portun operasyonel durumu DOWN'a geçti (admin durumu UP iken).</p>
                <ul>
                    <li>Şiddet: <strong>HIGH</strong></li>
                    <li>Admin DOWN portlarda tetiklenmez (kasıtlı kapatma)</li>
                    <li>VLAN dışlama listesindeki portlarda tetiklenmez</li>
                    <li>Port tekrar UP gelince otomatik çözülür</li>
                </ul>
            </div>

            <div class="type-card">
                <h4><span class="badge badge-success"><i class="fas fa-plug"></i> port_up</span></h4>
                <p><strong>Tetiklenme:</strong> Daha önce DOWN olan port operasyonel olarak UP'a geçti.</p>
                <ul>
                    <li>Şiddet: <strong>MEDIUM</strong></li>
                    <li>Yalnızca kanal yapılandırmasında etkinleştirilmişse bildirim gönderilir</li>
                    <li>Mevcut port_down alarmını otomatik çözer</li>
                </ul>
            </div>

            <div class="type-card">
                <h4><span class="badge badge-danger"><i class="fas fa-server"></i> device_unreachable</span></h4>
                <p><strong>Tetiklenme:</strong> Cihaz art arda yapılandırılmış eşik kadar SNMP isteğine yanıt vermedi.</p>
                <ul>
                    <li>Şiddet: <strong>CRITICAL</strong></li>
                    <li>Eşik (unreachable_threshold) sayıda ardışık başarısız poll sonrası tetiklenir</li>
                    <li>Cihaz tekrar erişilir olunca otomatik çözülür</li>
                </ul>
            </div>

            <div class="type-card">
                <h4><span class="badge badge-danger"><i class="fas fa-network-wired"></i> core_link_down</span></h4>
                <p><strong>Tetiklenme:</strong> Admin panelinde tanımlanmış bir core uplink portu DOWN'a geçti.</p>
                <ul>
                    <li>Şiddet: <strong>CRITICAL</strong></li>
                    <li>snmp_core_ports tablosunda kayıtlı portlarda tetiklenir</li>
                    <li>Hangi core switch'e bağlantının kesildiği alarmda belirtilir</li>
                    <li>Eş zamanlı olarak normal port_down alarmı da açılır</li>
                    <li>Port UP gelince otomatik çözülür</li>
                </ul>
            </div>

            <div class="type-card" style="border-color:rgba(245,158,11,.4);">
                <h4><span class="badge badge-warning"><i class="fas fa-bug"></i> snmp_error</span>
                    <span style="font-size:11px;color:var(--warning);margin-left:8px;"><i class="fas fa-tools"></i> Henüz üretilmiyor</span>
                </h4>
                <p><strong>Tetiklenme:</strong> Cihaza SNMP sorgusu sırasında kritik bir hata oluştu (timeout dışı).</p>
                <ul>
                    <li>Şiddet: <strong>HIGH</strong></li>
                    <li>Community string hatası, OID desteklenmemesi vb. durumlarda tetiklenir</li>
                    <li>SNMP konfigürasyonunu kontrol etmek gerekir</li>
                    <li style="color:var(--warning);"><i class="fas fa-exclamation-triangle"></i> Bu alarm türü Python worker'da henüz implement edilmemiştir. SNMP hataları şu anda sadece log dosyasına yazılır, alarm üretilmez.</li>
                </ul>
            </div>

        </div>
    </div>

    <!-- ================================================================ -->
    <!-- Suppression Rules                                                  -->
    <!-- ================================================================ -->
    <div class="section">
        <div class="section-title"><i class="fas fa-shield-alt"></i> Alarm Baskılama / Susturma Kuralları</div>

        <div class="supp-rule">
            <strong><i class="fas fa-redo"></i> Port Boşaltma Sonrası Aynı MAC (Yeni Kural — SW19 Düzeltmesi)</strong>
            <span>Port tablosu temizlendiğinde (boşa çek), eğer SNMP snapshotunda aynı MAC hâlâ mevcutsa <em>veya</em> MAC tracking'de bu MAC daha önce aynı portta kayıtlıysa alarm oluşturulmaz.</span>
        </div>

        <div class="supp-rule">
            <strong><i class="fas fa-wifi"></i> AP / Yönetilen Port İstemci MAC'leri</strong>
            <span>ports.mac'te kayıtlı beklenen MAC varken görülen ekstra MAC'ler (WiFi istemcileri) sessizce tracking'e eklenir, alarm açılmaz.</span>
        </div>

        <div class="supp-rule">
            <strong><i class="fas fa-layer-group"></i> Hub / Çok MAC'li Port</strong>
            <span>Herhangi bir anda portta 2+ MAC görülüyorsa port hub port olarak sınıflandırılır. MAC eklendi/kaldırıldı olayları alarm üretmez, yalnızca tracking güncellenir.</span>
        </div>

        <div class="supp-rule">
            <strong><i class="fas fa-link"></i> Uplink / Trunk Portlar</strong>
            <span>Tanımlanan uplink portlarda (Po1 benzeri backbone portlar) MAC değişikliği alarmı hiç üretilmez, sadece durum (up/down) izlenir.</span>
        </div>

        <div class="supp-rule">
            <strong><i class="fas fa-broadcast-tower"></i> WiFi SSID VLAN Geçişleri (VLAN 30/40/50/130/140/254 ↔ 70) — Sadece AP Portlarında</strong>
            <span>AP VLAN (70) ile WiFi SSID VLAN'ları arasındaki geçişler ve bu VLAN'lar arasındaki değişimler, yalnızca <strong>ports tablosunda kayıtlı MAC'i olan portlarda</strong> VLAN alarmı üretmez (AP SSID rotasyonu). Kayıtlı MAC'i olmayan normal erişim portları bu süzgeçten etkilenmez — her VLAN değişiminde alarm oluşur.</span>
        </div>

        <div class="supp-rule">
            <strong><i class="fas fa-search"></i> İlk Tarama</strong>
            <span>Switch sisteme ilk kez eklendiğinde, tüm portlar için ilk snapshot oluşturulur. Bu taramada alarm üretilmez (flood koruması).</span>
        </div>

        <div class="supp-rule">
            <strong><i class="fas fa-volume-mute"></i> Manuel Sessizleştirme</strong>
            <span>Kullanıcılar alarmları belirli bir süre için sessizleştirebilir. Sessizleştirme süresi dolduğunda alarm tekrar aktif hale gelir.</span>
        </div>

        <div class="supp-rule">
            <strong><i class="fas fa-filter"></i> Belirli VLAN'lar (Suppress Listesi)</strong>
            <span>Yapılandırmada tanımlanan belirli VLAN'lardaki portlar, MAC değişikliği izlemesinden tamamen muaf tutulabilir.</span>
        </div>
    </div>

    <!-- ================================================================ -->
    <!-- Detection Flow                                                     -->
    <!-- ================================================================ -->
    <div class="section">
        <div class="section-title"><i class="fas fa-sitemap"></i> MAC Alarm Karar Akışı</div>
        <div class="flow">
            <div class="flow-step">
                <strong><i class="fas fa-clock" style="color:var(--primary)"></i> SNMP Poll</strong>
                <span>Her <?php echo $pollInterval; ?> saniyede tüm portlar taranır</span>
            </div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">
                <strong><i class="fas fa-database" style="color:var(--secondary)"></i> Snapshot Karşılaştır</strong>
                <span>Önceki snapshot ile fark bul</span>
            </div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">
                <strong><i class="fas fa-filter" style="color:var(--warning)"></i> Baskılama Kontrolleri</strong>
                <span>Hub? AP? Uplink? VLAN suppress?</span>
            </div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">
                <strong><i class="fas fa-search" style="color:var(--success)"></i> MAC Tracking Sorgula</strong>
                <span>Bu MAC daha önce bu portta mıydı?</span>
            </div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">
                <strong><i class="fas fa-check-circle" style="color:var(--success)"></i> Alarm Kararı</strong>
                <span>Yeni / taşındı / aynı → Alarm?</span>
            </div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">
                <strong><i class="fas fa-bell" style="color:var(--danger)"></i> Bildirim</strong>
                <span>E-posta / Telegram gönder</span>
            </div>
        </div>

        <!-- Single-MAC Decision Priority Rules -->
        <div style="margin-top:24px;">
            <div style="font-size:14px; font-weight:700; color:var(--text); margin-bottom:14px; display:flex; align-items:center; gap:8px;">
                <i class="fas fa-code-branch" style="color:var(--primary);"></i>
                Tek MAC Karar Öncelik Sırası
            </div>
            <table class="matrix-table" style="font-size:13px;">
                <thead>
                    <tr>
                        <th>Kural</th>
                        <th>Koşul</th>
                        <th>ports.mac (beklenen)</th>
                        <th>MAC Tracking</th>
                        <th>Device Registry</th>
                        <th>Sonuç</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="badge badge-neutral">İlk Tarama</span></td>
                        <td>Önceki snapshot hiç yok</td>
                        <td>—</td>
                        <td>—</td>
                        <td>—</td>
                        <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span><br><small style="color:var(--text-light);">Baseline oluştur</small></td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-neutral">Uplink / Hub / AP / VLAN Suppress</span></td>
                        <td>Özel port türü veya baskılama kuralı</td>
                        <td>—</td>
                        <td>—</td>
                        <td>—</td>
                        <td><span class="check-no"><i class="fas fa-times-circle"></i> MAC Alarmı Yok</span><br><small style="color:var(--text-light);">Sadece tracking güncellenir</small></td>
                    </tr>
                    <tr style="background:rgba(16,185,129,0.04);">
                        <td><span class="badge badge-success">A1</span></td>
                        <td>ports.mac <strong>dolu</strong>, SNMP aynı MAC görüyor</td>
                        <td><span class="badge badge-success">Kayıtlı MAC var</span></td>
                        <td>—</td>
                        <td>—</td>
                        <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span><br><small style="color:var(--text-light);">Normal durum</small></td>
                    </tr>
                    <tr style="background:rgba(239,68,68,0.04);">
                        <td><span class="badge badge-danger">A2</span></td>
                        <td>ports.mac <strong>dolu</strong>, SNMP farklı MAC görüyor</td>
                        <td><span class="badge badge-danger">Farklı MAC kayıtlı</span></td>
                        <td>—</td>
                        <td>—</td>
                        <td><span class="check-yes"><i class="fas fa-check-circle"></i> <strong>mac_moved</strong></span><br><small style="color:var(--text-light);">Cihaz değiştirildi</small></td>
                    </tr>
                    <tr style="background:rgba(16,185,129,0.04);">
                        <td><span class="badge badge-neutral">B1</span></td>
                        <td>ports.mac <strong>boş</strong>, önceki snapshot'ta aynı MAC var</td>
                        <td><span class="badge badge-neutral">Boş</span></td>
                        <td><span class="badge badge-success">same_port_current</span></td>
                        <td>—</td>
                        <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span><br><small style="color:var(--text-light);">Port tablosu temizlendi, MAC sürekli var</small></td>
                    </tr>
                    <tr style="background:rgba(245,158,11,0.04);">
                        <td><span class="badge badge-warning">B2 + kayıtlı</span></td>
                        <td>ports.mac boş, snapshot boş (kısa çevrimdışı), aynı MAC döndü, <strong>kayıtlı</strong></td>
                        <td><span class="badge badge-neutral">Boş</span></td>
                        <td><span class="badge badge-success">same_port_previous</span></td>
                        <td><span class="badge badge-success">registry_known</span></td>
                        <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span><br><small style="color:var(--text-light);">Bilinen cihaz, kısa kesinti</small></td>
                    </tr>
                    <tr style="background:rgba(239,68,68,0.04);">
                        <td><span class="badge badge-danger">B2 + kayıtsız</span></td>
                        <td>ports.mac boş, snapshot boş (kısa çevrimdışı), aynı MAC döndü, <strong>kayıtsız</strong></td>
                        <td><span class="badge badge-neutral">Boş</span></td>
                        <td><span class="badge badge-success">same_port_previous</span></td>
                        <td><span class="badge badge-danger">registry_unknown</span></td>
                        <td><span class="check-yes"><i class="fas fa-check-circle"></i> <strong>mac_added</strong></span><br><small style="color:var(--text-light);">Kayıt yapılması için</small></td>
                    </tr>
                    <tr style="background:rgba(239,68,68,0.04);">
                        <td><span class="badge badge-danger">B3 — taşındı</span></td>
                        <td>ports.mac boş, bu MAC başka porttan geliyor</td>
                        <td><span class="badge badge-neutral">Boş</span></td>
                        <td><span class="badge badge-warning">moved_from_other_port</span></td>
                        <td>—</td>
                        <td><span class="check-yes"><i class="fas fa-check-circle"></i> <strong>mac_moved</strong></span><br><small style="color:var(--text-light);">Farklı porttan geldi</small></td>
                    </tr>
                    <tr style="background:rgba(239,68,68,0.04);">
                        <td><span class="badge badge-danger">B3 — yeni</span></td>
                        <td>ports.mac boş, MAC hiç görülmedi, kayıtsız</td>
                        <td><span class="badge badge-neutral">Boş</span></td>
                        <td><span class="badge badge-danger">tracking_same_port = false</span></td>
                        <td><span class="badge badge-danger">registry_unknown</span></td>
                        <td><span class="check-yes"><i class="fas fa-check-circle"></i> <strong>mac_added</strong></span><br><small style="color:var(--text-light);">Tamamen yeni cihaz</small></td>
                    </tr>
                    <tr style="background:rgba(16,185,129,0.04);">
                        <td><span class="badge badge-neutral">B3 — kayıtlı</span></td>
                        <td>ports.mac boş, MAC hiç görülmedi, ama kayıtlı</td>
                        <td><span class="badge badge-neutral">Boş</span></td>
                        <td><span class="badge badge-danger">tracking_same_port = false</span></td>
                        <td><span class="badge badge-success">registry_known</span></td>
                        <td><span class="check-no"><i class="fas fa-times-circle"></i> Alarm Yok</span><br><small style="color:var(--text-light);">Sadece tracking güncellenir</small></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- ================================================================ -->
    <!-- Active Alarms Table                                                -->
    <!-- ================================================================ -->
    <div class="section">
        <div class="section-title">
            <i class="fas fa-bell"></i> Aktif Alarmlar
            <span style="font-size:13px; color:var(--text-light); font-weight:400;">(Son 30 alarm &mdash; önce kritik)</span>
        </div>
        <?php if (empty($recentAlarms)): ?>
            <div style="text-align:center; padding:40px; color:var(--success);">
                <i class="fas fa-check-circle" style="font-size:48px; margin-bottom:12px; display:block;"></i>
                <strong>Aktif alarm bulunmuyor.</strong>
            </div>
        <?php else: ?>
        <div style="overflow-x:auto;">
        <table class="matrix-table">
            <thead>
                <tr>
                    <th>Switch</th>
                    <th>IP</th>
                    <th>Port</th>
                    <th>Alarm Türü</th>
                    <th>Şiddet</th>
                    <th>MAC / Değer</th>
                    <th>Mesaj</th>
                    <th>Tekrar</th>
                    <th>İlk Görülme</th>
                    <th>Son Görülme</th>
                    <th>Durum</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $typeLabels = [
                    'mac_added'           => ['badge-danger',    'plus-circle',    'MAC Eklendi'],
                    'mac_moved'           => ['badge-warning',   'random',         'MAC Taşındı'],
                    'vlan_changed'        => ['badge-primary',   'project-diagram','VLAN Değişti'],
                    'description_changed' => ['badge-primary',   'tag',            'Açıklama Değişti'],
                    'port_down'           => ['badge-danger',    'ethernet',       'Port Kapandı'],
                    'port_up'             => ['badge-success',   'plug',           'Port Açıldı'],
                    'device_unreachable'  => ['badge-danger',    'server',         'Cihaz Erişilemez'],
                    'core_link_down'      => ['badge-danger',    'network-wired',  'Core Uplink Kesildi'],
                ];
                foreach ($recentAlarms as $a):
                    $t = $a['alarm_type'];
                    [$cls,$ico,$lbl] = $typeLabels[$t] ?? ['badge-neutral','question-circle', htmlspecialchars($t)];

                    // Build a concise value/mac string
                    $valStr = '';
                    if (!empty($a['mac_address'])) $valStr = htmlspecialchars($a['mac_address']);
                    elseif (!empty($a['old_value']) || !empty($a['new_value'])) {
                        $valStr = htmlspecialchars($a['old_value'] ?? '—') . ' → ' . htmlspecialchars($a['new_value'] ?? '—');
                    }

                    // Silence / acknowledged indicator
                    $isSilenced = !empty($a['silence_until']) && strtotime($a['silence_until']) > time();
                    $isAcked    = !empty($a['acknowledged_at']);
                ?>
                <tr>
                    <td><strong><?php echo htmlspecialchars($a['device_name'] ?? '—'); ?></strong></td>
                    <td style="font-family:monospace;font-size:12px;color:var(--text-light);"><?php echo htmlspecialchars($a['device_ip'] ?? '—'); ?></td>
                    <td><?php echo htmlspecialchars($a['port_number'] ?? '—'); ?></td>
                    <td><span class="badge <?php echo $cls; ?>"><i class="fas fa-<?php echo $ico; ?>"></i> <?php echo $lbl; ?></span></td>
                    <td><span class="severity-<?php echo htmlspecialchars($a['severity'] ?? 'INFO'); ?>"><?php echo htmlspecialchars($a['severity'] ?? '—'); ?></span></td>
                    <td style="font-family:monospace;font-size:12px;max-width:160px;word-break:break-all;"><?php echo $valStr ?: '—'; ?></td>
                    <td style="font-size:12px;color:var(--text-light);max-width:200px;">
                        <?php echo htmlspecialchars(mb_strimwidth($a['title'] ?? $a['message'] ?? '', 0, 80, '…')); ?>
                    </td>
                    <td><?php echo (int)($a['occurrence_count'] ?? 0); ?></td>
                    <td style="font-size:12px;color:var(--text-light);white-space:nowrap;">
                        <?php echo $a['first_occurrence'] ? date('d.m.Y H:i', strtotime($a['first_occurrence'])) : '—'; ?>
                    </td>
                    <td style="font-size:12px;color:var(--text-light);white-space:nowrap;">
                        <?php echo $a['last_occurrence'] ? date('d.m.Y H:i', strtotime($a['last_occurrence'])) : '—'; ?>
                    </td>
                    <td style="white-space:nowrap;">
                        <?php if ($isSilenced): ?>
                            <span class="badge badge-secondary" title="Susturuldu: <?php echo date('d.m H:i', strtotime($a['silence_until'])); ?>">
                                <i class="fas fa-volume-mute"></i> Sessiz
                            </span>
                        <?php elseif ($isAcked): ?>
                            <span class="badge badge-neutral" title="Onaylayan: <?php echo htmlspecialchars($a['acknowledged_by'] ?? ''); ?>">
                                <i class="fas fa-check"></i> Onaylandı
                            </span>
                        <?php else: ?>
                            <span class="badge badge-danger"><i class="fas fa-exclamation"></i> Aktif</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <?php endif; ?>
    </div>

    <!-- ================================================================ -->
    <!-- Footer                                                             -->
    <!-- ================================================================ -->
    <div style="text-align:center; padding: 20px 0 30px; color:var(--text-light); font-size:13px;">
        <i class="fas fa-info-circle"></i>
        Bu sayfa her yenilemede veritabanından canlı veri çeker &mdash;
        <a href="matris.php">Yenile</a> &middot;
        <a href="port_alarms.php">Aktif Alarmlar</a> &middot;
        <a href="../index.php">Dashboard</a>
    </div>

</div>
</body>
</html>
