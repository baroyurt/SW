<!-- Port Alarms Component - Embedded in Index -->
<style>
.alarms-section {
    background: var(--dark-light);
    border-radius: 15px;
    padding: 25px;
    margin: 20px 0;
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
}

.alarms-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.alarms-title {
    font-size: 24px;
    font-weight: bold;
    color: var(--text);
}

.alarms-stats {
    display: flex;
    gap: 15px;
}

.alarm-stat {
    background: rgba(255, 255, 255, 0.1);
    padding: 8px 15px;
    border-radius: 20px;
    font-size: 14px;
}

.alarm-stat.critical { border: 2px solid var(--danger); }
.alarm-stat.high { border: 2px solid var(--warning); }

.alarms-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    flex-wrap: wrap;
    gap: 10px;
}

.alarm-filters {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

.filter-chip {
    padding: 6px 12px;
    border-radius: 15px;
    border: 2px solid var(--primary);
    background: transparent;
    color: var(--primary);
    cursor: pointer;
    transition: all 0.3s;
    font-size: 13px;
}

.filter-chip:hover, .filter-chip.active {
    background: var(--primary);
    color: white;
}

.alarm-actions-toolbar {
    display: flex;
    gap: 10px;
    align-items: center;
}

.bulk-actions {
    display: none;
    align-items: center;
    gap: 10px;
    background: rgba(59, 130, 246, 0.2);
    padding: 8px 15px;
    border-radius: 10px;
}

.bulk-actions.visible {
    display: flex;
}

.alarm-card {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 12px;
    border-left: 4px solid;
    transition: all 0.3s;
    position: relative;
}

.alarm-card:hover {
    background: rgba(255, 255, 255, 0.08);
    transform: translateX(5px);
}

.alarm-card.critical { border-left-color: var(--danger); }
.alarm-card.high { border-left-color: var(--warning); }
.alarm-card.medium { border-left-color: #fbbf24; }
.alarm-card.low { border-left-color: var(--success); }

.alarm-card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 12px;
}

.alarm-checkbox {
    width: 20px;
    height: 20px;
    margin-right: 12px;
    cursor: pointer;
}

.alarm-device {
    font-size: 18px;
    font-weight: bold;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 10px;
}

.alarm-badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: bold;
    color: white;
}

.badge-critical { background: var(--danger); }
.badge-high { background: var(--warning); }
.badge-medium { background: #fbbf24; }
.badge-low { background: var(--success); }

.alarm-details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin: 12px 0;
}

.alarm-detail-item {
    background: rgba(0, 0, 0, 0.2);
    padding: 10px;
    border-radius: 8px;
}

.alarm-detail-label {
    font-size: 11px;
    color: var(--text-light);
    margin-bottom: 4px;
}

.alarm-detail-value {
    font-size: 14px;
    color: var(--text);
    font-weight: 500;
}

.mac-address {
    background: rgba(139, 92, 246, 0.2);
    padding: 3px 8px;
    border-radius: 5px;
    font-family: 'Courier New', monospace;
    color: var(--secondary);
}

.change-indicator {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 10px 0;
    padding: 10px;
    background: rgba(59, 130, 246, 0.1);
    border-radius: 8px;
}

.change-old {
    text-decoration: line-through;
    color: var(--text-light);
}

.change-arrow {
    color: var(--primary);
    font-size: 18px;
}

.change-new {
    color: var(--success);
    font-weight: bold;
}

.alarm-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
}

.alarm-time {
    font-size: 12px;
    color: var(--text-light);
}

.alarm-counter {
    background: rgba(239, 68, 68, 0.2);
    padding: 3px 8px;
    border-radius: 10px;
    font-size: 11px;
    color: var(--danger);
    font-weight: bold;
}

.alarm-actions {
    display: flex;
    gap: 8px;
}

.alarm-btn {
    padding: 8px 16px;
    border-radius: 8px;
    border: none;
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
    transition: all 0.3s;
    display: flex;
    align-items: center;
    gap: 6px;
}

.alarm-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.btn-acknowledge {
    background: var(--success);
    color: white;
}

.btn-acknowledge:hover {
    background: #059669;
}

.btn-silence {
    background: var(--warning);
    color: #000;
}

.btn-silence:hover {
    background: #f59e0b;
}

.btn-details {
    background: var(--primary);
    color: white;
}

.btn-details:hover {
    background: var(--primary-dark);
}

.no-alarms {
    text-align: center;
    padding: 60px 20px;
    color: var(--text-light);
}

.no-alarms i {
    font-size: 64px;
    margin-bottom: 20px;
    opacity: 0.3;
}

/* Modal Styles */
.alarm-modal {
    display: none;
    position: fixed;
    z-index: 10000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.7);
    backdrop-filter: blur(5px);
}

.alarm-modal.show {
    display: flex;
    justify-content: center;
    align-items: center;
}

.alarm-modal-content {
    background: var(--dark-light);
    padding: 30px;
    border-radius: 15px;
    width: 90%;
    max-width: 500px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.modal-title {
    font-size: 20px;
    font-weight: bold;
    color: var(--text);
}

.modal-close {
    font-size: 28px;
    cursor: pointer;
    color: var(--text-light);
    transition: color 0.3s;
}

.modal-close:hover {
    color: var(--text);
}

.form-group {
    margin-bottom: 20px;
}

.form-label {
    display: block;
    margin-bottom: 8px;
    color: var(--text);
    font-weight: 500;
}

.form-input, .form-textarea {
    width: 100%;
    padding: 12px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--dark);
    color: var(--text);
    font-family: inherit;
}

.form-textarea {
    resize: vertical;
    min-height: 80px;
}
</style>

<div class="alarms-section" id="alarmsSection">
    <div class="alarms-header">
        <div>
            <div class="alarms-title">
                <i class="fas fa-bell"></i> Port Alarms
            </div>
            <div class="alarm-time" id="lastUpdateTime">Last updated: --:--</div>
        </div>
        <div class="alarms-stats">
            <div class="alarm-stat critical">
                <i class="fas fa-exclamation-circle"></i> Critical: <strong id="criticalCount">0</strong>
            </div>
            <div class="alarm-stat high">
                <i class="fas fa-exclamation-triangle"></i> High: <strong id="highCount">0</strong>
            </div>
        </div>
    </div>
    
    <div class="alarms-toolbar">
        <div class="alarm-filters">
            <button class="filter-chip active" data-filter="all">
                <i class="fas fa-list"></i> Tümü
            </button>
            <button class="filter-chip" data-filter="mac_moved">
                <i class="fas fa-exchange-alt"></i> MAC Taşındı
            </button>
            <button class="filter-chip" data-filter="vlan_changed">
                <i class="fas fa-network-wired"></i> VLAN Değişti
            </button>
            <button class="filter-chip" data-filter="description_changed">
                <i class="fas fa-edit"></i> Açıklama
            </button>
        </div>
        
        <div class="alarm-actions-toolbar">
            <div class="bulk-actions" id="bulkActions">
                <span id="selectedCount">0 selected</span>
                <button class="alarm-btn btn-acknowledge" onclick="bulkAcknowledge()">
                    <i class="fas fa-check"></i> Acknowledge Selected
                </button>
            </div>
            <button class="alarm-btn btn-details" onclick="refreshAlarms()">
                <i class="fas fa-sync-alt"></i> Refresh
            </button>
        </div>
    </div>
    
    <div id="alarmsContainer">
        <div class="loading">
            <i class="fas fa-spinner fa-spin" style="font-size: 48px; color: var(--primary);"></i>
            <p style="margin-top: 20px; color: var(--text-light);">Loading alarms...</p>
        </div>
    </div>
</div>

<!-- Acknowledge Modal -->
<div id="acknowledgeModal" class="alarm-modal">
    <div class="alarm-modal-content">
        <div class="modal-header">
            <div class="modal-title">Acknowledge Alarm</div>
            <span class="modal-close" onclick="closeAcknowledgeModal()">&times;</span>
        </div>
        <p style="color: var(--text-light); margin-bottom: 20px;">
            Are you sure you want to acknowledge this alarm? This will permanently whitelist the MAC+Port combination.
        </p>
        <div class="form-group">
            <label class="form-label">Note (optional):</label>
            <textarea id="ackNote" class="form-textarea" placeholder="Add a note about this change..."></textarea>
        </div>
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
            <button class="alarm-btn" onclick="closeAcknowledgeModal()" style="background: var(--border);">
                Cancel
            </button>
            <button class="alarm-btn btn-acknowledge" onclick="confirmAcknowledge()">
                <i class="fas fa-check"></i> Acknowledge
            </button>
        </div>
    </div>
</div>

<!-- MAC Taşıma Modal -->
<div id="macMoveModal" class="alarm-modal">
    <div class="alarm-modal-content">
        <div class="modal-header">
            <div class="modal-title"><i class="fas fa-exchange-alt"></i> MAC Adresi Taşındı</div>
            <span class="modal-close" onclick="closeMacMoveModal()">&times;</span>
        </div>
        <div style="background: rgba(59,130,246,0.1); padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <p style="color: var(--text);">Bu MAC adresi daha önce tespit edildi.</p>
            <p style="margin-top: 8px;"><strong>MAC:</strong> <span id="mmMac" class="mac-address"></span></p>
            <p style="margin-top: 8px;"><strong>Önceki Port:</strong> <span id="mmOldPort" style="color: var(--warning); font-weight: bold;"></span></p>
            <p style="margin-top: 4px;"><strong>Yeni Port:</strong> <span id="mmNewPort" style="color: var(--success); font-weight: bold;"></span></p>
        </div>
        <p style="color: var(--text-light); margin-bottom: 20px;">Bu MAC adresi yeni porta taşınsın mı?</p>
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
            <button class="alarm-btn" onclick="closeMacMoveModal()" style="background: var(--border);">
                <i class="fas fa-times"></i> HAYIR
            </button>
            <button class="alarm-btn" style="background: var(--success); color: white;" onclick="confirmMacMove()">
                <i class="fas fa-check"></i> EVET
            </button>
        </div>
    </div>
</div>

<!-- Device Registry Found Modal -->
<div id="deviceRegistryModal" class="alarm-modal">
    <div class="alarm-modal-content">
        <div class="modal-header">
            <div class="modal-title"><i class="fas fa-database"></i> Cihaz Kaydı Bulundu</div>
            <span class="modal-close" onclick="closeDeviceRegistryModal()">&times;</span>
        </div>
        <p style="color: var(--text-light); margin-bottom: 15px;">Bu MAC Device Import listesinde mevcut. Bilgiler aşağıdadır:</p>
        <div id="deviceRegistryInfo" style="background: rgba(16,185,129,0.1); padding: 15px; border-radius: 8px; margin-bottom: 20px;"></div>
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
            <button class="alarm-btn" onclick="closeDeviceRegistryModal()" style="background: var(--border);">
                <i class="fas fa-times"></i> İptal
            </button>
            <button class="alarm-btn" style="background: var(--success); color: white;" onclick="confirmDeviceRegistry()">
                <i class="fas fa-save"></i> Onayla ve Kaydet
            </button>
        </div>
    </div>
</div>

<!-- New Device Registration Modal -->
<div id="newDeviceModal" class="alarm-modal">
    <div class="alarm-modal-content" style="max-width: 560px;">
        <div class="modal-header">
            <div class="modal-title"><i class="fas fa-plus-circle"></i> Yeni Cihaz Kaydı</div>
        </div>
        <p style="color: var(--warning); margin-bottom: 15px;">
            <i class="fas fa-exclamation-triangle"></i>
            Bu MAC adresi sistemde yeni. Cihaz kaydı yapılmadan alarm kapatılamaz.
        </p>
        <p style="color: var(--text-light); margin-bottom: 15px;">
            MAC: <span id="ndMac" class="mac-address"></span>
        </p>
        <div class="form-group">
            <label class="form-label">Cihaz Adı <span style="color:var(--danger)">*</span></label>
            <input type="text" id="ndDeviceName" class="form-input" placeholder="Örn: PC-MUHASEBE-01" required>
        </div>
        <div class="form-group">
            <label class="form-label">IP Adresi</label>
            <input type="text" id="ndIpAddress" class="form-input" placeholder="Örn: 192.168.1.100">
        </div>
        <div class="form-group">
            <label class="form-label">Lokasyon</label>
            <input type="text" id="ndLocation" class="form-input" placeholder="Örn: 3. Kat - Muhasebe">
        </div>
        <div class="form-group">
            <label class="form-label">Açıklama</label>
            <input type="text" id="ndDescription" class="form-input" placeholder="Cihaz hakkında not...">
        </div>
        <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 10px;">
            <button class="alarm-btn" onclick="closeNewDeviceModal()" style="background: var(--border);">
                <i class="fas fa-times"></i> İptal
            </button>
            <button class="alarm-btn" style="background: var(--success); color: white;" onclick="confirmNewDevice()">
                <i class="fas fa-save"></i> Kaydet ve Alarmı Kapat
            </button>
        </div>
    </div>
</div>

<script>
// Global variables for alarm management
let currentAlarmId = null;
let selectedAlarms = new Set();
let currentFilter = 'all';
let alarmsData = [];

// MAC workflow state
let macWorkflowData = {};

// Auto-refresh interval (30 seconds)
let refreshInterval = setInterval(refreshAlarms, 30000);

// Load alarms on page load
document.addEventListener('DOMContentLoaded', function() {
    refreshAlarms();
    
    // Setup filter buttons
    document.querySelectorAll('.filter-chip').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.filter-chip').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            currentFilter = this.dataset.filter;
            filterAlarms();
        });
    });
});

async function refreshAlarms() {
    try {
        const response = await fetch('port_change_api.php?action=get_active_alarms');
        const data = await response.json();
        
        if (data.success) {
            alarmsData = data.alarms;
            displayAlarms(data.alarms);
            updateStats(data.alarms);
            updateLastUpdateTime();
        } else {
            showError('Failed to load alarms: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        showError('Error loading alarms: ' + error.message);
    }
}

function updateStats(alarms) {
    const critical = alarms.filter(a => a.severity === 'CRITICAL').length;
    const high = alarms.filter(a => a.severity === 'HIGH').length;
    
    document.getElementById('criticalCount').textContent = critical;
    document.getElementById('highCount').textContent = high;
}

function updateLastUpdateTime() {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('tr-TR');
    document.getElementById('lastUpdateTime').textContent = `Last updated: ${timeStr}`;
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
        const severityClass = alarm.severity.toLowerCase();
        const occurrences = alarm.occurrence_count > 1 ? 
            `<span class="alarm-counter"><i class="fas fa-redo"></i> ${alarm.occurrence_count}x</span>` : '';
        
        html += `
            <div class="alarm-card ${severityClass}" data-alarm-id="${alarm.id}" data-alarm-type="${alarm.alarm_type}">
                <div class="alarm-card-header">
                    <div style="display: flex; align-items: center; flex: 1;">
                        <input type="checkbox" class="alarm-checkbox" data-alarm-id="${alarm.id}" 
                               onchange="toggleAlarmSelection(${alarm.id})">
                        <div>
                            <div class="alarm-device">
                                <i class="fas fa-network-wired"></i>
                                <span>${alarm.device_name}</span>
                                <span style="color: var(--text-light);">Port ${alarm.port_number || 'N/A'}</span>
                                <span class="alarm-badge badge-${severityClass}">${alarm.severity}</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="alarm-details-grid">
                    <div class="alarm-detail-item">
                        <div class="alarm-detail-label">Type</div>
                        <div class="alarm-detail-value">${formatAlarmType(alarm.alarm_type)}</div>
                    </div>
                    <div class="alarm-detail-item">
                        <div class="alarm-detail-label">Device IP</div>
                        <div class="alarm-detail-value">${alarm.device_ip}</div>
                    </div>
                    <div class="alarm-detail-item">
                        <div class="alarm-detail-label">First Seen</div>
                        <div class="alarm-detail-value">${formatDateTime(alarm.first_occurrence)}</div>
                    </div>
                    <div class="alarm-detail-item">
                        <div class="alarm-detail-label">Last Seen</div>
                        <div class="alarm-detail-value">${formatDateTime(alarm.last_occurrence)}</div>
                    </div>
                </div>
                
                <div style="margin: 12px 0;">
                    <strong>${alarm.title}</strong>
                    <p style="margin-top: 6px; color: var(--text-light); font-size: 14px;">${alarm.message}</p>
                </div>
                
                ${alarm.mac_address ? `
                    <div style="margin: 10px 0;">
                        <strong>MAC:</strong> <span class="mac-address">${alarm.mac_address}</span>
                    </div>
                ` : ''}
                
                ${alarm.old_value && alarm.new_value ? `
                    <div class="change-indicator">
                        <span class="change-old">${alarm.old_value}</span>
                        <span class="change-arrow"><i class="fas fa-arrow-right"></i></span>
                        <span class="change-new">${alarm.new_value}</span>
                    </div>
                ` : ''}
                
                <div class="alarm-footer">
                    <div>
                        ${occurrences}
                    </div>
                    <div class="alarm-actions">
                        ${(alarm.alarm_type === 'mac_moved' || alarm.alarm_type === 'mac_added') && alarm.new_value ? `
                            <button class="alarm-btn" style="background: #27ae60; color: white; font-weight: bold;"
                                onclick="startMacWorkflow(${alarm.id}, '${alarm.new_value}', ${alarm.device_id || 0}, ${alarm.port_number || 0}, '${alarm.device_name || ''}', '${alarm.device_ip || ''}', '${alarm.old_value || ''}')">
                                <i class="fas fa-exchange-alt"></i> MAC İşle
                            </button>
                        ` : ''}
                        <button class="alarm-btn btn-acknowledge" onclick="showAcknowledgeModal(${alarm.id})">
                            <i class="fas fa-check"></i> Bilgi Dahilinde Kapat
                        </button>
                        <button class="alarm-btn btn-details" onclick="navigateToDevice('${alarm.device_name}', ${alarm.port_number})">
                            <i class="fas fa-external-link-alt"></i> View Port
                        </button>
                    </div>
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
    if (!dateStr) return 'N/A';
    const normalized = typeof dateStr === 'string' ? dateStr.replace(' ', 'T') : dateStr;
    const date = new Date(normalized);
    return date.toLocaleString('tr-TR');
}

function toggleAlarmSelection(alarmId) {
    if (selectedAlarms.has(alarmId)) {
        selectedAlarms.delete(alarmId);
    } else {
        selectedAlarms.add(alarmId);
    }
    
    updateBulkActionsVisibility();
}

function updateBulkActionsVisibility() {
    const bulkActions = document.getElementById('bulkActions');
    const selectedCount = document.getElementById('selectedCount');
    
    if (selectedAlarms.size > 0) {
        bulkActions.classList.add('visible');
        selectedCount.textContent = `${selectedAlarms.size} selected`;
    } else {
        bulkActions.classList.remove('visible');
    }
}

// ─────────────────────────────────────────────────────────────────
//  MAC WORKFLOW  (replaces old saveMacAndCloseAlarmComponent)
// ─────────────────────────────────────────────────────────────────

async function startMacWorkflow(alarmId, newMac, deviceId, portNumber, deviceName, deviceIp, oldMac) {
    // Store context for later steps
    macWorkflowData = { alarmId, newMac, deviceId, portNumber, deviceName, deviceIp, oldMac };

    try {
        // Step 1: Was this MAC previously on another port?
        const resp = await fetch(
            `port_change_api.php?action=check_mac_previous_port&device_id=${deviceId}&mac_address=${encodeURIComponent(newMac)}&port_number=${portNumber}`
        );
        const data = await resp.json();

        if (data.success && data.found) {
            // Show "move" confirmation popup
            macWorkflowData.previousPort = data.previous_port;
            document.getElementById('mmMac').textContent     = newMac;
            document.getElementById('mmOldPort').textContent = data.previous_port;
            document.getElementById('mmNewPort').textContent = portNumber;
            document.getElementById('macMoveModal').classList.add('show');
        } else {
            // Step 2: Is this MAC in the device registry?
            await checkMacInRegistry(newMac);
        }
    } catch (err) {
        showNotification('Hata: ' + err.message, 'error');
    }
}

async function checkMacInRegistry(mac) {
    try {
        const resp = await fetch(
            `port_change_api.php?action=check_device_in_registry&mac_address=${encodeURIComponent(mac)}`
        );
        const data = await resp.json();

        if (data.success && data.found) {
            // Show device info popup
            const d = data.device;
            let html = '';
            if (d.device_name) html += `<p><strong>Cihaz Adı:</strong> ${d.device_name}</p>`;
            if (d.ip_address)  html += `<p><strong>IP:</strong> ${d.ip_address}</p>`;
            if (d.location)    html += `<p><strong>Lokasyon:</strong> ${d.location}</p>`;
            if (d.notes)       html += `<p><strong>Açıklama:</strong> ${d.notes}</p>`;
            if (d.department)  html += `<p><strong>Departman:</strong> ${d.department}</p>`;
            document.getElementById('deviceRegistryInfo').innerHTML = html || '<p>Kayıt bulundu.</p>';
            macWorkflowData.registryDevice = d;
            document.getElementById('deviceRegistryModal').classList.add('show');
        } else {
            // Show mandatory registration form
            document.getElementById('ndMac').textContent = mac;
            document.getElementById('ndDeviceName').value  = '';
            document.getElementById('ndIpAddress').value   = '';
            document.getElementById('ndLocation').value    = '';
            document.getElementById('ndDescription').value = '';
            document.getElementById('newDeviceModal').classList.add('show');
        }
    } catch (err) {
        showNotification('Hata: ' + err.message, 'error');
    }
}

// ── MAC Move modal ──────────────────────────────────────────
function closeMacMoveModal() {
    document.getElementById('macMoveModal').classList.remove('show');
}

async function confirmMacMove() {
    const { alarmId, newMac, deviceId, portNumber, previousPort, oldMac } = macWorkflowData;
    closeMacMoveModal();
    try {
        const resp = await fetch('port_change_api.php?action=move_mac_to_port', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alarm_id: alarmId,
                mac_address: newMac,
                device_id: deviceId,
                old_port: previousPort,
                new_port: portNumber
            })
        });
        const data = await resp.json();
        if (data.success) {
            showNotification(data.message || 'MAC porta taşındı ve alarm kapatıldı.', 'success');
            refreshAlarms();
        } else {
            showNotification('Hata: ' + (data.error || 'İşlem başarısız'), 'error');
        }
    } catch (err) {
        showNotification('Hata: ' + err.message, 'error');
    }
}

// ── Device Registry modal ────────────────────────────────────
function closeDeviceRegistryModal() {
    document.getElementById('deviceRegistryModal').classList.remove('show');
}

async function confirmDeviceRegistry() {
    const { alarmId, newMac, deviceId, portNumber, registryDevice } = macWorkflowData;
    closeDeviceRegistryModal();
    try {
        const resp = await fetch('port_change_api.php?action=register_device_for_alarm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alarm_id:    alarmId,
                mac_address: newMac,
                device_id:   deviceId,
                port_number: portNumber,
                device_name: registryDevice ? registryDevice.device_name : '',
                ip_address:  registryDevice ? registryDevice.ip_address  : '',
                location:    registryDevice ? registryDevice.location    : '',
                description: registryDevice ? registryDevice.notes       : ''
            })
        });
        const data = await resp.json();
        if (data.success) {
            showNotification(data.message || 'Cihaz kaydedildi ve alarm kapatıldı.', 'success');
            refreshAlarms();
        } else {
            showNotification('Hata: ' + (data.error || 'İşlem başarısız'), 'error');
        }
    } catch (err) {
        showNotification('Hata: ' + err.message, 'error');
    }
}

// ── New Device modal ─────────────────────────────────────────
function closeNewDeviceModal() {
    document.getElementById('newDeviceModal').classList.remove('show');
}

async function confirmNewDevice() {
    const { alarmId, newMac, deviceId, portNumber } = macWorkflowData;
    const deviceName = document.getElementById('ndDeviceName').value.trim();
    if (!deviceName) {
        showNotification('Cihaz Adı zorunludur!', 'error');
        return;
    }
    closeNewDeviceModal();
    try {
        const resp = await fetch('port_change_api.php?action=register_device_for_alarm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alarm_id:    alarmId,
                mac_address: newMac,
                device_id:   deviceId,
                port_number: portNumber,
                device_name: deviceName,
                ip_address:  document.getElementById('ndIpAddress').value.trim(),
                location:    document.getElementById('ndLocation').value.trim(),
                description: document.getElementById('ndDescription').value.trim()
            })
        });
        const data = await resp.json();
        if (data.success) {
            showNotification(data.message || 'Cihaz kaydedildi ve alarm kapatıldı.', 'success');
            refreshAlarms();
        } else {
            showNotification('Hata: ' + (data.error || 'İşlem başarısız'), 'error');
        }
    } catch (err) {
        showNotification('Hata: ' + err.message, 'error');
    }
}

// ─────────────────────────────────────────────────────────────────

function showAcknowledgeModal(alarmId) {
    currentAlarmId = alarmId;
    document.getElementById('acknowledgeModal').classList.add('show');
}

function closeAcknowledgeModal() {
    document.getElementById('acknowledgeModal').classList.remove('show');
    document.getElementById('ackNote').value = '';
    currentAlarmId = null;
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
            closeAcknowledgeModal();
            refreshAlarms();
            showNotification('Alarm acknowledged successfully', 'success');
        } else {
            showNotification('Error: ' + (data.error || 'Failed to acknowledge alarm'), 'error');
        }
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
    }
}

async function bulkAcknowledge() {
    if (selectedAlarms.size === 0) {
        showNotification('Please select alarms first', 'warning');
        return;
    }
    
    if (!confirm(`Acknowledge ${selectedAlarms.size} alarm(s)? This will whitelist all selected MAC+Port combinations.`)) {
        return;
    }
    
    try {
        const formData = new FormData();
        formData.append('action', 'bulk_acknowledge');
        formData.append('alarm_ids', JSON.stringify(Array.from(selectedAlarms)));
        formData.append('ack_type', 'known_change');
        formData.append('note', 'Bulk acknowledged');
        
        const response = await fetch('port_change_api.php', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            selectedAlarms.clear();
            updateBulkActionsVisibility();
            refreshAlarms();
            showNotification(data.message, 'success');
        } else {
            showNotification('Error: ' + (data.error || 'Failed to acknowledge alarms'), 'error');
        }
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
    }
}

function navigateToDevice(deviceName, portNumber) {
    // Find the device card in the main content
    const deviceCards = document.querySelectorAll('.device-card');
    
    for (let card of deviceCards) {
        const cardTitle = card.querySelector('.device-header h3');
        if (cardTitle && cardTitle.textContent.includes(deviceName)) {
            // Scroll to device card
            card.scrollIntoView({ behavior: 'smooth', block: 'start' });
            
            // Highlight the device card
            card.style.border = '3px solid var(--warning)';
            setTimeout(() => {
                card.style.border = '';
            }, 3000);
            
            // If port number is specified, try to highlight the port
            if (portNumber) {
                setTimeout(() => {
                    const portBoxes = card.querySelectorAll('.port-box');
                    portBoxes.forEach(box => {
                        if (box.textContent.includes(`Port ${portNumber}`)) {
                            box.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            box.style.boxShadow = '0 0 20px var(--warning)';
                            setTimeout(() => {
                                box.style.boxShadow = '';
                            }, 3000);
                        }
                    });
                }, 500);
            }
            
            break;
        }
    }
}

function showNotification(message, type = 'info') {
    // You can implement a toast notification system here
    // For now, using alert
    if (type === 'error') {
        alert('❌ ' + message);
    } else if (type === 'success') {
        alert('✅ ' + message);
    } else {
        alert('ℹ️ ' + message);
    }
}

function showError(message) {
    document.getElementById('alarmsContainer').innerHTML = `
        <div style="text-align: center; padding: 40px; color: var(--danger);">
            <i class="fas fa-exclamation-triangle" style="font-size: 48px; margin-bottom: 20px;"></i>
            <h3>Error</h3>
            <p>${message}</p>
            <button class="alarm-btn btn-details" onclick="refreshAlarms()" style="margin-top: 20px;">
                <i class="fas fa-redo"></i> Retry
            </button>
        </div>
    `;
}
</script>
