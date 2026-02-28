<?php
// Require authentication
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

$currentUser = $auth->getUser();
?>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Change Alarms - Switch Management</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 20px;
        }
        
        .header h1 {
            color: #667eea;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .stats-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card .value {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-card.critical .value { color: #dc3545; }
        .stat-card.high .value { color: #fd7e14; }
        .stat-card.medium .value { color: #ffc107; }
        .stat-card.info .value { color: #17a2b8; }
        
        .alarms-container {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .alarm-card {
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.3s;
            position: relative;
        }
        
        .alarm-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .alarm-card.critical {
            border-left: 5px solid #dc3545;
            background: #fff5f5;
        }
        
        .alarm-card.high {
            border-left: 5px solid #fd7e14;
            background: #fff9f0;
        }
        
        .alarm-card.medium {
            border-left: 5px solid #ffc107;
            background: #fffef0;
        }
        
        .alarm-card.silenced {
            opacity: 0.6;
            border-style: dashed;
        }
        
        .alarm-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .alarm-title {
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }
        
        .alarm-severity {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        
        .severity-CRITICAL { background: #dc3545; }
        .severity-HIGH { background: #fd7e14; }
        .severity-MEDIUM { background: #ffc107; color: #333; }
        .severity-LOW { background: #28a745; }
        .severity-INFO { background: #17a2b8; }
        
        .alarm-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .detail-item {
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .detail-label {
            font-size: 12px;
            color: #666;
            margin-bottom: 5px;
        }
        
        .detail-value {
            font-size: 14px;
            font-weight: bold;
            color: #333;
        }
        
        .mac-highlight {
            background: #fff3cd;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        .change-indicator {
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 10px 0;
            padding: 10px;
            background: #e3f2fd;
            border-radius: 5px;
        }
        
        .change-indicator .old-value {
            text-decoration: line-through;
            color: #999;
        }
        
        .change-indicator .arrow {
            font-size: 20px;
            color: #667eea;
        }
        
        .change-indicator .new-value {
            color: #28a745;
            font-weight: bold;
        }
        
        .alarm-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 3px 10px rgba(0,0,0,0.2);
        }
        
        .btn-acknowledge {
            background: #28a745;
            color: white;
        }
        
        .btn-acknowledge:hover {
            background: #218838;
        }
        
        .btn-silence {
            background: #ffc107;
            color: #333;
        }
        
        .btn-silence:hover {
            background: #e0a800;
        }
        
        .btn-details {
            background: #17a2b8;
            color: white;
        }
        
        .btn-details:hover {
            background: #138496;
        }
        
        .filter-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 2px solid #667eea;
            background: white;
            color: #667eea;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .filter-btn:hover,
        .filter-btn.active {
            background: #667eea;
            color: white;
        }
        
        .timestamp {
            font-size: 12px;
            color: #999;
            font-style: italic;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .no-alarms {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }
        
        .no-alarms i {
            font-size: 64px;
            margin-bottom: 20px;
            opacity: 0.3;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background: white;
            margin: min(100px, 10vh) auto;
            padding: 30px;
            border-radius: 15px;
            width: 90%;
            max-width: 600px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            max-height: calc(100vh - 200px);
            overflow-y: auto;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .modal-header h2 {
            color: #667eea;
        }
        
        .close {
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: #999;
        }
        
        .close:hover {
            color: #333;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #333;
        }
        
        .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-family: inherit;
        }
        
        .auto-refresh {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
            background: white;
            border-radius: 10px;
        }
        
        .auto-refresh input[type="checkbox"] {
            width: 20px;
            height: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-bell"></i> Port Change Alarms</h1>
            <p>Real-time monitoring of MAC movements, VLAN changes, and port configuration updates</p>
            <div class="auto-refresh">
                <input type="checkbox" id="autoRefresh" checked>
                <label for="autoRefresh">Auto-refresh every 30 seconds</label>
            </div>
        </div>
        
        <div class="stats-bar" id="statsBar">
            <div class="stat-card critical">
                <div><i class="fas fa-exclamation-circle"></i> Critical</div>
                <div class="value" id="criticalCount">0</div>
            </div>
            <div class="stat-card high">
                <div><i class="fas fa-exclamation-triangle"></i> High</div>
                <div class="value" id="highCount">0</div>
            </div>
            <div class="stat-card medium">
                <div><i class="fas fa-info-circle"></i> Medium</div>
                <div class="value" id="mediumCount">0</div>
            </div>
            <div class="stat-card info">
                <div><i class="fas fa-check-circle"></i> Total Active</div>
                <div class="value" id="totalCount">0</div>
            </div>
        </div>
        
        <div class="alarms-container">
            <h2 style="margin-bottom: 15px;"><i class="fas fa-list"></i> Aktif Alarmlar</h2>
            
            <div class="filter-bar">
                <button class="filter-btn active" data-filter="all">Tümü</button>
                <button class="filter-btn" data-filter="mac_moved">MAC Taşındı</button>
                <button class="filter-btn" data-filter="vlan_changed">VLAN Değişti</button>
                <button class="filter-btn" data-filter="description_changed">Açıklama Değişti</button>
                <button class="filter-btn" data-filter="silenced" style="border-color: #999; color: #999;">Sessize Alındı</button>
            </div>
            
            <div id="alarmsContainer">
                <div class="loading">
                    <div class="spinner"></div>
                    <p>Loading alarms...</p>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Acknowledge Modal -->
    <div id="acknowledgeModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Acknowledge Alarm</h2>
                <span class="close" onclick="closeModal('acknowledgeModal')">&times;</span>
            </div>
            <div class="form-group">
                <label>Note (Optional):</label>
                <textarea id="ackNote" rows="3" placeholder="Add a note about this change..."></textarea>
            </div>
            <div class="alarm-actions">
                <button class="btn btn-acknowledge" onclick="confirmAcknowledge()">
                    <i class="fas fa-check"></i> Acknowledge as Known Change
                </button>
            </div>
        </div>
    </div>
    
    <!-- Silence Modal -->
    <div id="silenceModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Silence Alarm</h2>
                <span class="close" onclick="closeModal('silenceModal')">&times;</span>
            </div>
            <div class="form-group">
                <label>Silence Duration:</label>
                <select id="silenceDuration" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <option value="1">1 Hour</option>
                    <option value="4">4 Hours</option>
                    <option value="24" selected>24 Hours</option>
                    <option value="168">7 Days</option>
                </select>
            </div>
            <div class="alarm-actions">
                <button class="btn btn-silence" onclick="confirmSilence()">
                    <i class="fas fa-volume-mute"></i> Silence Alarm
                </button>
            </div>
        </div>
    </div>
    
    <script>
        let currentAlarmId = null;
        let currentFilter = 'all';
        let refreshInterval = null;
        
        // Load alarms on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadAlarms();
            
            // Setup filter buttons
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    currentFilter = this.dataset.filter;
                    filterAlarms();
                });
            });
            
            // Setup auto-refresh
            document.getElementById('autoRefresh').addEventListener('change', function() {
                if (this.checked) {
                    startAutoRefresh();
                } else {
                    stopAutoRefresh();
                }
            });
            
            startAutoRefresh();
        });
        
        function startAutoRefresh() {
            refreshInterval = setInterval(loadAlarms, 30000); // 30 seconds
        }
        
        function stopAutoRefresh() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
                refreshInterval = null;
            }
        }
        
        async function loadAlarms() {
            try {
                const response = await fetch('port_change_api.php?action=get_active_alarms');
                const data = await response.json();
                
                if (data.success) {
                    displayAlarms(data.alarms);
                    updateStats(data.alarms);
                } else {
                    showError('Failed to load alarms: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                showError('Error loading alarms: ' + error.message);
            }
        }
        
        function updateStats(alarms) {
            // Filter only non-silenced and active alarms
            const activeAlarms = alarms.filter(a => !a.is_silenced && a.status === 'ACTIVE');
            
            const critical = activeAlarms.filter(a => a.severity === 'CRITICAL').length;
            const high = activeAlarms.filter(a => a.severity === 'HIGH').length;
            const medium = activeAlarms.filter(a => a.severity === 'MEDIUM').length;
            
            document.getElementById('criticalCount').textContent = critical;
            document.getElementById('highCount').textContent = high;
            document.getElementById('mediumCount').textContent = medium;
            document.getElementById('totalCount').textContent = activeAlarms.length;
        }
        
        function displayAlarms(alarms) {
            const container = document.getElementById('alarmsContainer');
            
            if (alarms.length === 0) {
                container.innerHTML = `
                    <div class="no-alarms">
                        <i class="fas fa-check-circle"></i>
                        <h3>No Active Alarms</h3>
                        <p>All systems are operating normally</p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            
            alarms.forEach(alarm => {
                const isSilenced = alarm.is_silenced == 1;
                const severityClass = alarm.severity.toLowerCase();
                
                html += `
                    <div class="alarm-card ${severityClass} ${isSilenced ? 'silenced' : ''}" data-alarm-type="${alarm.alarm_type}" data-alarm-id="${alarm.id}">
                        <div class="alarm-header">
                            <div class="alarm-title">
                                <i class="fas fa-network-wired"></i> ${alarm.device_name} - Port ${alarm.port_number || 'N/A'}
                            </div>
                            <span class="alarm-severity severity-${alarm.severity}">${alarm.severity}</span>
                        </div>
                        
                        <div class="alarm-details">
                            <div class="detail-item">
                                <div class="detail-label">Alarm Type</div>
                                <div class="detail-value">${formatAlarmType(alarm.alarm_type)}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Switch IP</div>
                                <div class="detail-value">${alarm.device_ip}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">First Occurrence</div>
                                <div class="detail-value">${formatDateTime(alarm.first_occurrence)}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Last Occurrence</div>
                                <div class="detail-value">${formatDateTime(alarm.last_occurrence)}</div>
                            </div>
                        </div>
                        
                        <div style="margin: 15px 0;">
                            <strong>${alarm.title}</strong>
                            <p style="margin: 10px 0; color: #666;">${alarm.message}</p>
                        </div>
                        
                        ${alarm.mac_address ? `
                            <div style="margin: 10px 0;">
                                <strong>MAC Address:</strong> <span class="mac-highlight">${alarm.mac_address}</span>
                            </div>
                        ` : ''}
                        
                        ${alarm.old_value && alarm.new_value ? `
                            <div class="change-indicator">
                                <span class="old-value">${alarm.old_value}</span>
                                <span class="arrow"><i class="fas fa-arrow-right"></i></span>
                                <span class="new-value">${alarm.new_value}</span>
                            </div>
                        ` : ''}
                        
                        ${isSilenced ? `
                            <div style="padding: 10px; background: #fff3cd; border-radius: 5px; margin: 10px 0;">
                                <i class="fas fa-volume-mute"></i> <strong>Silenced until:</strong> ${formatDateTime(alarm.silence_until)}
                            </div>
                        ` : ''}
                        
                        ${alarm.acknowledged_at ? `
                            <div style="padding: 10px; background: #d4edda; border-radius: 5px; margin: 10px 0;">
                                <i class="fas fa-check"></i> <strong>Acknowledged by:</strong> ${alarm.acknowledged_by} on ${formatDateTime(alarm.acknowledged_at)}
                            </div>
                        ` : ''}
                        
                        <div class="alarm-actions">
                            ${!alarm.acknowledged_at ? `
                                <button class="btn btn-acknowledge" onclick="showAcknowledgeModal(${alarm.id})">
                                    <i class="fas fa-check"></i> Bilgi Dahilinde Kapat
                                </button>
                            ` : ''}
                            ${!isSilenced ? `
                                <button class="btn btn-silence" onclick="showSilenceModal(${alarm.id})">
                                    <i class="fas fa-volume-mute"></i> Alarmı Sesize Al
                                </button>
                            ` : ''}
                            <button class="btn btn-details" onclick="showAlarmDetails(${alarm.id}, ${alarm.device_id}, ${alarm.port_number})">
                                <i class="fas fa-eye"></i> View Port
                            </button>
                        </div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
            filterAlarms();
        }
        
        function filterAlarms() {
            const cards = document.querySelectorAll('.alarm-card');
            
            cards.forEach(card => {
                if (currentFilter === 'all') {
                    card.style.display = 'block';
                } else if (currentFilter === 'silenced') {
                    card.style.display = card.classList.contains('silenced') ? 'block' : 'none';
                } else {
                    card.style.display = card.dataset.alarmType === currentFilter ? 'block' : 'none';
                }
            });
        }
        
        function formatAlarmType(type) {
            const types = {
                'mac_moved': 'MAC Taşındı',
                'mac_added': 'MAC Added',
                'vlan_changed': 'VLAN Değişti',
                'description_changed': 'Açıklama Değişti',
                'port_down': 'Port Kapandı',
                'device_unreachable': 'Device Unreachable'
            };
            return types[type] || type;
        }
        
        function formatDateTime(dateStr) {
            const normalized = typeof dateStr === 'string' ? dateStr.replace(' ', 'T') : dateStr;
            const date = new Date(normalized);
            return date.toLocaleString('tr-TR');
        }
        
        function showAcknowledgeModal(alarmId) {
            currentAlarmId = alarmId;
            document.getElementById('acknowledgeModal').style.display = 'block';
        }
        
        function showSilenceModal(alarmId) {
            currentAlarmId = alarmId;
            document.getElementById('silenceModal').style.display = 'block';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        async function confirmAcknowledge() {
            const note = document.getElementById('ackNote').value;
            
            try {
                const formData = new FormData();
                formData.append('action', 'acknowledge_alarm');
                formData.append('alarm_id', currentAlarmId);
                formData.append('ack_type', 'known_change');
                formData.append('note', note);
                
                const response = await fetch('port_change_api.php', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    closeModal('acknowledgeModal');
                    document.getElementById('ackNote').value = '';
                    loadAlarms();
                } else {
                    alert('Error: ' + (data.error || 'Failed to acknowledge alarm'));
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
        
        async function confirmSilence() {
            const duration = document.getElementById('silenceDuration').value;
            
            try {
                const formData = new FormData();
                formData.append('action', 'silence_alarm');
                formData.append('alarm_id', currentAlarmId);
                formData.append('duration_hours', duration);
                
                const response = await fetch('port_change_api.php', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    closeModal('silenceModal');
                    loadAlarms();
                } else {
                    alert('Error: ' + (data.error || 'Failed to silence alarm'));
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
        
        function showAlarmDetails(alarmId, deviceId, portNumber) {
            // Open a new window or modal with detailed history
            window.open(`port_history.php?device_id=${deviceId}&port_number=${portNumber}`, '_blank');
        }
        
        function showError(message) {
            document.getElementById('alarmsContainer').innerHTML = `
                <div style="text-align: center; padding: 40px; color: #dc3545;">
                    <i class="fas fa-exclamation-triangle" style="font-size: 48px; margin-bottom: 20px;"></i>
                    <h3>Error</h3>
                    <p>${message}</p>
                    <button class="btn btn-details" onclick="loadAlarms()" style="margin-top: 20px;">
                        <i class="fas fa-redo"></i> Retry
                    </button>
                </div>
            `;
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
        }
    </script>
</body>
</html>
