<?php
// Require authentication
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

$currentUser = $auth->getUser();

// Prevent caching
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Fetch alarm data server-side to avoid CORS issues in sandboxed iframe
function getActiveAlarmsData($conn) {
    $columns_to_select = "a.id, a.device_id, a.alarm_type, a.severity, a.status,
                a.port_number, a.title, a.message, a.details,
                a.occurrence_count, a.first_occurrence, a.last_occurrence,
                a.acknowledged_at, a.acknowledged_by, a.acknowledgment_type,
                a.silence_until, a.mac_address, a.old_value, a.new_value";
    
    // Try to check if columns exist
    $result = $conn->query("SHOW COLUMNS FROM alarms LIKE 'from_port'");
    if ($result && $result->num_rows > 0) {
        $columns_to_select .= ", a.from_port, a.to_port";
    } else {
        $columns_to_select .= ", NULL as from_port, NULL as to_port";
    }
    
    // Check for VLAN columns
    $result = $conn->query("SHOW COLUMNS FROM alarms LIKE 'old_vlan_id'");
    if ($result && $result->num_rows > 0) {
        $columns_to_select .= ", a.old_vlan_id, a.new_vlan_id";
    } else {
        $columns_to_select .= ", NULL as old_vlan_id, NULL as new_vlan_id";
    }
    
    $sql = "SELECT 
                $columns_to_select,
                d.name as device_name, d.ip_address as device_ip,
                CASE 
                    WHEN a.silence_until > NOW() THEN 1
                    ELSE 0
                END as is_silenced,
                CASE
                    WHEN a.alarm_type IN ('mac_moved', 'mac_added', 'vlan_changed', 'description_changed') THEN 1
                    ELSE 0
                END as is_port_change
            FROM alarms a
            LEFT JOIN snmp_devices d ON a.device_id = d.id
            WHERE a.status = 'ACTIVE'
            ORDER BY 
                CASE a.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    WHEN 'INFO' THEN 5
                END,
                a.last_occurrence DESC";
    
    $result = $conn->query($sql);
    $alarms = [];
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $alarms[] = $row;
        }
    }
    
    return $alarms;
}

$alarmsData = getActiveAlarmsData($conn);
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Change Alarms - Switch Management</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #0f172a;
            --dark-light: #1e293b;
            --text: #e2e8f0;
            --text-light: #94a3b8;
            --border: #334155;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--dark);
            color: var(--text);
            padding: 20px;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .header {
            background: var(--dark-light);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            margin-bottom: 20px;
            border: 1px solid var(--border);
        }
        
        .header h1 {
            color: var(--primary);
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header p {
            color: var(--text-light);
            font-size: 14px;
        }
        
        .stats-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: var(--dark-light);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            text-align: center;
            border: 1px solid var(--border);
            transition: all 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.3);
        }
        
        .stat-card .label {
            color: var(--text-light);
            font-size: 14px;
            margin-bottom: 8px;
        }
        
        .stat-card .value {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-card.critical .value { color: var(--danger); }
        .stat-card.high .value { color: var(--warning); }
        .stat-card.medium .value { color: #fbbf24; }
        .stat-card.info .value { color: var(--primary); }
        
        .toolbar {
            background: var(--dark-light);
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
            border: 1px solid var(--border);
        }
        
        .filter-group {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 1px solid var(--border);
            background: var(--dark);
            color: var(--text);
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .filter-btn:hover {
            background: var(--primary);
            border-color: var(--primary);
            color: white;
        }
        
        .filter-btn.active {
            background: var(--primary);
            border-color: var(--primary);
            color: white;
        }
        
        .refresh-btn {
            padding: 8px 16px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s;
        }
        
        .refresh-btn:hover {
            background: var(--primary-dark);
        }
        
        .alarms-container {
            background: var(--dark-light);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            border: 1px solid var(--border);
        }
        
        .alarm-card {
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.3s;
            position: relative;
            background: var(--dark);
        }
        
        .alarm-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }
        
        .alarm-card.critical {
            border-left: 5px solid var(--danger);
            background: rgba(239, 68, 68, 0.1);
        }
        
        .alarm-card.high {
            border-left: 5px solid var(--warning);
            background: rgba(245, 158, 11, 0.1);
        }
        
        .alarm-card.medium {
            border-left: 5px solid #fbbf24;
            background: rgba(251, 191, 36, 0.1);
        }
        
        .alarm-card.silenced {
            opacity: 0.6;
            border-left-color: var(--text-light);
        }
        
        .alarm-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }
        
        .alarm-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 5px;
        }
        
        .alarm-severity {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .alarm-severity.critical { background: var(--danger); color: white; }
        .alarm-severity.high { background: var(--warning); color: white; }
        .alarm-severity.medium { background: #fbbf24; color: #1e293b; }
        
        .alarm-info {
            color: var(--text-light);
            font-size: 14px;
            margin-bottom: 12px;
        }
        
        .alarm-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
            padding: 15px;
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
        }
        
        .info-item {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        
        .info-label {
            font-size: 12px;
            color: var(--text-light);
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .info-value {
            font-size: 14px;
            color: var(--text);
        }
        
        .alarm-additional-info {
            background: rgba(255,255,255,0.05);
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 15px;
            font-size: 13px;
            color: var(--text-light);
        }
        
        .alarm-additional-info div {
            margin-bottom: 5px;
        }
        
        .alarm-additional-info div:last-child {
            margin-bottom: 0;
        }
        
        .alarm-message {
            color: var(--text);
            margin-bottom: 15px;
            line-height: 1.5;
        }
        
        .alarm-details {
            background: rgba(255,255,255,0.05);
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 15px;
            font-size: 13px;
            color: var(--text-light);
        }
        
        .alarm-meta {
            display: flex;
            gap: 20px;
            font-size: 12px;
            color: var(--text-light);
            flex-wrap: wrap;
        }
        
        .alarm-meta span {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .alarm-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--primary-dark);
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-danger:hover {
            background: #dc2626;
        }
        
        .btn-secondary {
            background: var(--dark);
            color: var(--text);
            border: 1px solid var(--border);
        }
        
        .btn-secondary:hover {
            background: var(--border);
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-light);
        }
        
        .empty-state i {
            font-size: 64px;
            margin-bottom: 20px;
            color: var(--success);
        }
        
        .empty-state h3 {
            color: var(--text);
            margin-bottom: 10px;
        }
        
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 9999;
            backdrop-filter: blur(5px);
        }
        
        .modal-overlay.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .modal {
            background: var(--dark-light);
            border-radius: 15px;
            padding: 30px;
            max-width: 500px;
            width: 90%;
            border: 1px solid var(--border);
        }
        
        .modal-header {
            margin-bottom: 20px;
        }
        
        .modal-title {
            color: var(--primary);
            font-size: 20px;
            margin-bottom: 10px;
        }
        
        .modal-actions {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
            margin-top: 20px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: var(--text);
            font-weight: 600;
        }
        
        .form-group input, .form-group textarea, .form-group select {
            width: 100%;
            padding: 10px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: var(--dark);
            color: var(--text);
            font-size: 14px;
        }
        
        .form-group input:focus, .form-group textarea:focus, .form-group select:focus {
            outline: none;
            border-color: var(--primary);
        }
        
        /* Improved card shadows and styling to match index.php */
        .stat-card {
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        
        .stat-card:hover {
            box-shadow: 0 8px 12px rgba(0, 0, 0, 0.4);
            transform: translateY(-2px);
        }
        
        .alarm-card {
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        
        .alarm-card:hover {
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            transform: translateY(-2px);
        }
        
        /* Animation for pulse effect */
        @keyframes pulse {
            0%, 100% {
                box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.7);
            }
            50% {
                box-shadow: 0 0 0 20px rgba(59, 130, 246, 0);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-exclamation-triangle"></i> Port Değişiklik Alarmları</h1>
            <p>Port durumu değişiklikleri ve MAC adres hareketlerini izleyin</p>
        </div>
        
        <div class="stats-bar">
            <div class="stat-card critical">
                <div class="label">Kritik</div>
                <div class="value" id="criticalCount">0</div>
            </div>
            <div class="stat-card high">
                <div class="label">Yüksek</div>
                <div class="value" id="highCount">0</div>
            </div>
            <div class="stat-card medium">
                <div class="label">Orta</div>
                <div class="value" id="mediumCount">0</div>
            </div>
            <div class="stat-card info">
                <div class="label">Toplam Aktif</div>
                <div class="value" id="totalCount">0</div>
            </div>
        </div>
        
        <div class="toolbar">
            <div class="filter-group">
                <span style="color: var(--text-light); font-size: 14px;">Filtre:</span>
                <button class="filter-btn active" onclick="filterAlarms('all')">Tümü</button>
                <button class="filter-btn" onclick="filterAlarms('critical')">Kritik</button>
                <button class="filter-btn" onclick="filterAlarms('high')">Yüksek</button>
                <button class="filter-btn" onclick="filterAlarms('medium')">Orta</button>
            </div>
            <button class="refresh-btn" onclick="refreshPage()">
                <i class="fas fa-sync-alt"></i> Yenile
            </button>
        </div>
        
        <div class="alarms-container">
            <div id="alarms-list"></div>
        </div>
    </div>
    
    <!-- Acknowledge Modal -->
    <div class="modal-overlay" id="ackModal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Alarmı Kapat</h3>
            </div>
            <div class="form-group">
                <label>Onay Türü:</label>
                <select id="ackType">
                    <option value="known_change">Bilgi Dahilinde (Known Change)</option>
                    <option value="false_alarm">Yanlış Alarm (False Alarm)</option>
                    <option value="resolved">Çözüldü (Resolved)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Notlar (İsteğe Bağlı):</label>
                <textarea id="ackNotes" rows="3" placeholder="Not ekleyin..."></textarea>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeAckModal()">İptal</button>
                <button class="btn btn-primary" onclick="submitAcknowledge()">Onayla</button>
            </div>
        </div>
    </div>
    
    <!-- Silence Modal -->
    <div class="modal-overlay" id="silenceModal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Alarmı Sesize Al</h3>
            </div>
            <div class="form-group">
                <label>Sessize Alma Süresi:</label>
                <select id="silenceDuration">
                    <option value="30">30 dakika</option>
                    <option value="60">1 saat</option>
                    <option value="180">3 saat</option>
                    <option value="360">6 saat</option>
                    <option value="1440">24 saat</option>
                </select>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeSilenceModal()">İptal</button>
                <button class="btn btn-primary" onclick="submitSilence()">Sesize Al</button>
            </div>
        </div>
    </div>
    
    <script>
        // Alarm data loaded dynamically to avoid caching issues
        let alarmsData = [];
        let currentFilter = 'all';
        let selectedAlarmId = null;
        
        // Load alarms from API
        async function loadAlarms() {
            try {
                const response = await fetch('port_change_api.php?action=get_active_alarms');
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                
                if (data.success) {
                    alarmsData = data.alarms || [];
                    displayAlarms(alarmsData);
                    updateStats(alarmsData);
                } else {
                    console.error('Failed to load alarms:', data.error || data.message);
                }
            } catch (error) {
                console.error('Error loading alarms:', error);
            }
        }
        
        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadAlarms();  // Initial load
            
            // Auto-refresh every 30 seconds
            setInterval(loadAlarms, 30000);
        });
        
        function displayAlarms(alarms) {
            const container = document.getElementById('alarms-list');
            
            // Filter alarms based on current filter
            let filtered = alarms;
            if (currentFilter === 'critical') {
                filtered = alarms.filter(a => a.severity === 'CRITICAL' && !(a.is_silenced == 1 || a.is_silenced === true));
            } else if (currentFilter === 'high') {
                filtered = alarms.filter(a => a.severity === 'HIGH' && !(a.is_silenced == 1 || a.is_silenced === true));
            } else if (currentFilter === 'medium') {
                filtered = alarms.filter(a => a.severity === 'MEDIUM' && !(a.is_silenced == 1 || a.is_silenced === true));
            } else if (currentFilter === 'all') {
                filtered = alarms;
            }
            
            if (filtered.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-check-circle"></i>
                        <h3>Aktif Alarm Yok</h3>
                        <p>Tüm sistemler normal çalışıyor</p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            filtered.forEach(alarm => {
                const severityClass = alarm.severity.toLowerCase();
                const isSilenced = alarm.is_silenced == 1 || alarm.is_silenced === true;
                const silencedClass = isSilenced ? 'silenced' : '';
                const silencedBadge = isSilenced ? '<span style="background: var(--text-light); color: white; padding: 2px 8px; border-radius: 10px; font-size: 11px; margin-left: 10px;">SESSİZDE</span>' : '';
                
                // Get Turkish alarm type name
                const alarmTypeTurkish = getAlarmTypeTurkish(alarm.alarm_type);
                
                html += `
                    <div class="alarm-card ${severityClass} ${silencedClass}">
                        <div class="alarm-header">
                            <div style="flex: 1;">
                                <div class="alarm-title">${escapeHtml(alarm.device_name || 'Bilinmeyen Cihaz')} - Port ${alarm.port_number || 'N/A'}</div>
                            </div>
                            <span class="alarm-severity ${severityClass}">${alarm.severity}${silencedBadge}</span>
                        </div>
                        
                        <div class="alarm-info-grid">
                            <div class="info-item">
                                <span class="info-label">Alarm Türü:</span>
                                <span class="info-value">${alarmTypeTurkish}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Switch IP:</span>
                                <span class="info-value">${alarm.device_ip || 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">İlk Görülme:</span>
                                <span class="info-value">${formatDateFull(alarm.first_occurrence)}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Son Görülme:</span>
                                <span class="info-value">${formatDateFull(alarm.last_occurrence)}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Tekrar Sayısı:</span>
                                <span class="info-value"><strong>${alarm.occurrence_count || 1}</strong></span>
                            </div>
                        </div>
                        
                        <div class="alarm-message">${escapeHtml(alarm.message)}</div>
                        
                        ${alarm.details ? `<div class="alarm-details">${escapeHtml(alarm.details)}</div>` : ''}
                        
                        ${alarm.mac_address || alarm.old_value || alarm.new_value || alarm.old_vlan_id || alarm.new_vlan_id ? `
                            <div class="alarm-additional-info">
                                ${alarm.mac_address ? `<div><strong>MAC Address:</strong> ${alarm.mac_address}</div>` : ''}
                                ${alarm.old_value ? `<div><strong>Eski Değer:</strong> ${alarm.old_value}</div>` : ''}
                                ${alarm.new_value ? `<div><strong>Yeni Değer:</strong> ${alarm.new_value}</div>` : ''}
                                ${alarm.old_vlan_id ? `<div><strong>Eski VLAN ID:</strong> ${alarm.old_vlan_id}</div>` : ''}
                                ${alarm.new_vlan_id ? `<div><strong>Yeni VLAN ID:</strong> ${alarm.new_vlan_id}</div>` : ''}
                            </div>
                        ` : ''}
                        
                        <div class="alarm-actions">
                            <button class="btn btn-primary" onclick="openAckModal(${alarm.id})">
                                <i class="fas fa-check"></i> Bilgi Dahilinde Kapat
                            </button>
                            ${isSilenced ? `
                                <button class="btn btn-warning" onclick="unsilenceAlarm(${alarm.id})">
                                    <i class="fas fa-bell"></i> Sessizlikten Çıkar
                                </button>
                            ` : `
                                <button class="btn btn-secondary" onclick="openSilenceModal(${alarm.id})">
                                    <i class="fas fa-bell-slash"></i> Alarmı Sesize Al
                                </button>
                            `}
                            ${alarm.port_number ? `
                                <button class="btn btn-secondary" onclick="viewPort('${alarm.device_name}', ${alarm.port_number})">
                                    <i class="fas fa-eye"></i> View Port
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
        }
        
        function getAlarmTypeTurkish(alarmType) {
            const types = {
                'device_unreachable': 'Cihaz Erişilemez',
                'multiple_ports_down': 'Birden Fazla Port Kapalı',
                'mac_moved': 'MAC Taşındı',
                'mac_added': 'MAC Eklendi',
                'vlan_changed': 'VLAN Değişti',
                'description_changed': 'Açıklama Değişti',
                'port_up': 'Port Açıldı',
                'port_down': 'Port Kapandı',
                'snmp_error': 'SNMP Hatası'
            };
            return types[alarmType] || alarmType;
        }
        
        function formatDateFull(dateString) {
            if (!dateString) return 'N/A';
            const date = new Date(dateString);
            return date.toLocaleString('tr-TR', { 
                year: 'numeric', 
                month: '2-digit', 
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }
        
        function updateStats(alarms) {
            // Count all active alarms (including silenced)
            const activeAlarms = alarms.filter(a => a.status === 'ACTIVE');
            const nonSilencedAlarms = activeAlarms.filter(a => !(a.is_silenced == 1 || a.is_silenced === true));
            
            const critical = nonSilencedAlarms.filter(a => a.severity === 'CRITICAL').length;
            const high = nonSilencedAlarms.filter(a => a.severity === 'HIGH').length;
            const medium = nonSilencedAlarms.filter(a => a.severity === 'MEDIUM').length;
            
            document.getElementById('criticalCount').textContent = critical;
            document.getElementById('highCount').textContent = high;
            document.getElementById('mediumCount').textContent = medium;
            document.getElementById('totalCount').textContent = activeAlarms.length;
        }
        
        function filterAlarms(filter) {
            currentFilter = filter;
            
            // Update active button
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
                // Check if this button's onclick contains the current filter
                const onclick = btn.getAttribute('onclick');
                if (onclick && onclick.includes(`'${filter}'`)) {
                    btn.classList.add('active');
                }
            });
            
            displayAlarms(alarmsData);
        }
        
        function refreshPage() {
            loadAlarms();  // Reload alarm data instead of page
        }
        
        function openAckModal(alarmId) {
            selectedAlarmId = alarmId;
            document.getElementById('ackModal').classList.add('active');
        }
        
        function closeAckModal() {
            document.getElementById('ackModal').classList.remove('active');
            selectedAlarmId = null;
        }
        
        function openSilenceModal(alarmId) {
            selectedAlarmId = alarmId;
            document.getElementById('silenceModal').classList.add('active');
        }
        
        function closeSilenceModal() {
            document.getElementById('silenceModal').classList.remove('active');
            selectedAlarmId = null;
        }
        
        async function submitAcknowledge() {
            const ackType = document.getElementById('ackType').value;
            const notes = document.getElementById('ackNotes').value;
            
            try {
                const formData = new FormData();
                formData.append('action', 'acknowledge_alarm');
                formData.append('alarm_id', selectedAlarmId);
                formData.append('ack_type', ackType); // Fixed: was 'acknowledgment_type'
                if (notes) formData.append('note', notes); // Fixed: was 'notes'
                
                const response = await fetch('port_change_api.php', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    alert('Alarm başarıyla kapatıldı');
                    closeAckModal();
                    loadAlarms();  // Reload alarm data instead of page
                } else {
                    alert('Hata: ' + (data.error || 'Bilinmeyen hata'));
                }
            } catch (error) {
                alert('Hata: ' + error.message);
            }
        }
        
        async function submitSilence() {
            const durationMinutes = parseInt(document.getElementById('silenceDuration').value);
            const durationHours = durationMinutes / 60; // Convert minutes to hours
            
            try {
                const formData = new FormData();
                formData.append('action', 'silence_alarm');
                formData.append('alarm_id', selectedAlarmId);
                formData.append('duration_hours', durationHours); // Fixed: send hours instead of minutes
                
                const response = await fetch('port_change_api.php', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    alert('Alarm başarıyla sesize alındı');
                    closeSilenceModal();
                    loadAlarms();  // Reload alarm data instead of page
                } else {
                    alert('Hata: ' + (data.error || 'Bilinmeyen hata'));
                }
            } catch (error) {
                alert('Hata: ' + error.message);
            }
        }
        
        async function unsilenceAlarm(alarmId) {
            if (!confirm('Bu alarmı sessizlikten çıkarmak istiyor musunuz?')) {
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('action', 'unsilence_alarm');
                formData.append('alarm_id', alarmId);
                
                const response = await fetch('port_change_api.php', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    alert('Alarm sessizlikten çıkarıldı');
                    loadAlarms();  // Reload alarm data instead of page
                } else {
                    alert('Hata: ' + (data.error || 'Bilinmeyen hata'));
                }
            } catch (error) {
                alert('Hata: ' + error.message);
            }
        }
        
        function viewPort(deviceName, portNumber) {
            // Check if we're in an iframe
            if (window.parent !== window) {
                // We're in an iframe - communicate with parent
                window.parent.postMessage({
                    action: 'navigateToPort',
                    switchName: deviceName,
                    portNumber: portNumber
                }, '*');
            } else {
                // Standalone mode - navigate directly
                window.location.href = `index.php?switch=${encodeURIComponent(deviceName)}&port=${portNumber}`;
            }
        }
        
        function formatDate(dateString) {
            if (!dateString) return 'N/A';
            const date = new Date(dateString);
            return date.toLocaleString('tr-TR', { 
                year: 'numeric', 
                month: '2-digit', 
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            });
        }
        
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Close modals when clicking outside
        document.querySelectorAll('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', function(e) {
                if (e.target === this) {
                    this.classList.remove('active');
                    selectedAlarmId = null;
                }
            });
        });
    </script>
</body>
</html>
