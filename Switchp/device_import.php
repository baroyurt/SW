<?php
// Require authentication
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

$currentUser = $auth->getUser();
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Import - MAC Address Registry</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        :root {
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #0f172a;
            --dark-light: #1e293b;
            --text: #e2e8f0;
            --text-light: #94a3b8;
            --border: #334155;
        }
        
        body {
            background: linear-gradient(135deg, var(--dark) 0%, var(--dark-light) 100%);
            background-attachment: fixed;
            color: var(--text);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: linear-gradient(135deg, rgba(15,23,42,0.95) 0%, rgba(30,41,59,0.95) 100%);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
            margin-bottom: 20px;
            border: 1px solid rgba(56,189,248,0.15);
        }
        
        .header h1 {
            color: var(--primary);
            font-size: 28px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .header p {
            color: var(--text-light);
            line-height: 1.6;
        }
        
        .main-content {
            display: none; /* Replaced by collapsible button panels */
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        @media (max-width: 1024px) {
            .main-content {
                grid-template-columns: 1fr;
            }
        }
        
        .card {
            background: linear-gradient(135deg, rgba(15,23,42,0.8) 0%, rgba(30,41,59,0.8) 100%);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            border: 1px solid rgba(56,189,248,0.15);
            transition: border-color 0.3s;
        }
        .card:hover {
            border-color: rgba(56,189,248,0.3);
        }
        
        .card h2 {
            color: var(--primary);
            margin-bottom: 20px;
            font-size: 22px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .upload-area {
            border: 3px dashed var(--primary);
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            transition: all 0.3s;
            cursor: pointer;
            background: rgba(59, 130, 246, 0.05);
        }
        
        .upload-area:hover, .upload-area.drag-over {
            background: rgba(59, 130, 246, 0.1);
            border-color: var(--secondary);
        }
        
        .upload-area i {
            font-size: 48px;
            color: var(--primary);
            margin-bottom: 20px;
        }
        
        .upload-area p {
            color: var(--text);
            font-size: 16px;
            margin-bottom: 10px;
        }
        
        .upload-area .file-types {
            color: var(--text-light);
            font-size: 14px;
        }
        
        #file-input {
            display: none;
        }
        
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 10px;
        }
        
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(59, 130, 246, 0.4);
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-success:hover {
            background: #059669;
            transform: translateY(-2px);
        }
        
        .progress-bar {
            width: 100%;
            height: 30px;
            background: var(--dark);
            border-radius: 15px;
            overflow: hidden;
            margin-top: 20px;
            display: none;
            border: 1px solid var(--border);
        }
        
        .progress-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary) 0%, var(--secondary) 100%);
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        
        .result-message {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            display: none;
            border: 1px solid;
        }
        
        .result-message.success {
            background: rgba(16, 185, 129, 0.1);
            border-color: var(--success);
            color: var(--success);
        }
        
        .result-message.error {
            background: rgba(239, 68, 68, 0.1);
            border-color: var(--danger);
            color: var(--danger);
        }
        
        .instructions {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid var(--warning);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .instructions h3 {
            color: var(--warning);
            margin-bottom: 10px;
            font-size: 18px;
        }
        
        .instructions ol {
            margin-left: 20px;
            color: var(--text-light);
        }
        
        .instructions li {
            margin-bottom: 8px;
        }
        
        .template-download {
            margin-top: 20px;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--text);
            font-weight: 600;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--dark);
            color: var(--text);
            font-size: 16px;
            transition: all 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        .form-group input::placeholder {
            color: var(--text-light);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            background: var(--dark);
            color: var(--primary);
            font-weight: 600;
        }
        
        tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }
        
        .stat-box {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
        }
        
        .stat-box .value {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-box .label {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .error-list {
            max-height: 300px;
            overflow-y: auto;
            margin-top: 15px;
        }
        
        .error-item {
            padding: 8px;
            background: rgba(239, 68, 68, 0.1);
            border-left: 3px solid var(--danger);
            margin-bottom: 5px;
            border-radius: 3px;
            color: var(--danger);
        }
        
        code {
            background: var(--dark);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: var(--primary);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Action Buttons Row -->
        <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
            <button class="btn btn-primary" onclick="toggleSection('excel-section')" style="padding:12px 24px;font-size:1rem;">
                <i class="fas fa-upload"></i> Excel İçe Aktarma
            </button>
            <button class="btn btn-primary" onclick="toggleSection('manual-section')" style="padding:12px 24px;font-size:1rem;background:linear-gradient(135deg,#8b5cf6,#6d28d9);">
                <i class="fas fa-edit"></i> Manuel Giriş
            </button>
        </div>

        <!-- Excel Upload Popup Panel -->
        <div id="excel-section" style="display:none;margin-bottom:20px;">
        <div class="card" style="animation:fadeIn .25s ease;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <h2 style="margin:0;"><i class="fas fa-upload"></i> Excel İçe Aktarma</h2>
                <button onclick="toggleSection('excel-section')" style="background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:8px;padding:6px 12px;cursor:pointer;">✕ Kapat</button>
            </div>
            <div class="instructions">
                <h3><i class="fas fa-info-circle"></i> Excel Format:</h3>
                <ol>
                    <li>Sütun 1: <strong>IP Adresi</strong></li>
                    <li>Sütun 2: <strong>Hostname</strong></li>
                    <li>Sütun 3: <strong>MAC Adresi</strong></li>
                </ol>
                <p style="margin-top:10px;">Örnek: <code>192.0.2.10 | TEST-PC-01 | 00:11:22:33:44:55</code></p>
            </div>
            <div class="template-download">
                <button class="btn btn-primary" onclick="downloadTemplate()">
                    <i class="fas fa-download"></i> Excel Şablonu İndir
                </button>
            </div>
            <div class="upload-area" id="upload-area">
                <i class="fas fa-cloud-upload-alt"></i>
                <p><strong>Excel dosyanızı buraya sürükleyin</strong></p>
                <p>veya dosya seçmek için tıklayın</p>
                <p class="file-types">Desteklenen: .xlsx, .xls, .csv</p>
                <input type="file" id="file-input" accept=".xlsx,.xls,.csv">
            </div>
            <div class="progress-bar" id="progress-bar">
                <div class="progress-bar-fill" id="progress-fill">0%</div>
            </div>
            <div class="result-message" id="result-message"></div>
        </div>
        </div>

        <!-- Manual Entry Popup Panel -->
        <div id="manual-section" style="display:none;margin-bottom:20px;">
        <div class="card" style="animation:fadeIn .25s ease;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <h2 style="margin:0;"><i class="fas fa-edit"></i> Manuel Giriş</h2>
                <button onclick="toggleSection('manual-section')" style="background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:8px;padding:6px 12px;cursor:pointer;">✕ Kapat</button>
            </div>
            <form id="manual-form">
                <div class="form-group">
                    <label for="ip-address"><i class="fas fa-network-wired"></i> IP Adresi</label>
                    <input type="text" id="ip-address" placeholder="Örn: 192.0.2.10" required>
                </div>
                <div class="form-group">
                    <label for="hostname"><i class="fas fa-server"></i> Hostname</label>
                    <input type="text" id="hostname" placeholder="Örn: TEST-PC-01" required>
                </div>
                <div class="form-group">
                    <label for="mac-address"><i class="fas fa-ethernet"></i> MAC Adresi</label>
                    <input type="text" id="mac-address" placeholder="Örn: 00:11:22:33:44:55" required>
                </div>
                <button type="submit" class="btn btn-success" style="width:100%;">
                    <i class="fas fa-plus-circle"></i> Cihaz Ekle
                </button>
            </form>
            <div class="result-message" id="manual-result"></div>
            <div style="margin-top:20px;">
                <h3 style="color:var(--primary);margin-bottom:10px;"><i class="fas fa-info-circle"></i> Format Rehberi</h3>
                <ul style="color:var(--text-light);line-height:2;">
                    <li>IP: IPv4 formatı (örn. 192.168.1.1)</li>
                    <li>Hostname: Harf, rakam, tire ve alt çizgi</li>
                    <li>MAC: Herhangi bir format (normalleştirilir)</li>
                </ul>
            </div>
        </div>
        </div>

        <style>
        @keyframes fadeIn { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:translateY(0); } }
        </style>
        
        <!-- Device List -->
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px;">
                <h2 style="margin: 0;"><i class="fas fa-list"></i> Registered Devices</h2>
                
                <!-- Apply to Ports Button -->
                <button id="applyToPortsBtn" class="btn btn-success" onclick="applyDeviceImportToPorts()" 
                        style="background: var(--success); padding: 10px 20px;">
                    <i class="fas fa-download"></i> Portlara Uygula
                </button>
                
                <!-- Search Box -->
                <div style="position: relative; flex: 1; min-width: 300px; max-width: 500px;">
                    <input type="text" id="device-search" placeholder="🔍 Search by MAC, IP, or Hostname..." 
                           style="width: 100%; padding: 10px 40px 10px 15px; border-radius: 8px; border: 1px solid var(--border); background: var(--dark); color: var(--text); font-size: 14px;">
                    <button id="clear-search" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-light); cursor: pointer; display: none; font-size: 16px;">
                        <i class="fas fa-times-circle"></i>
                    </button>
                </div>
            </div>
            
            <div id="device-list">
                <p style="text-align: center; color: var(--text-light);">Loading devices...</p>
            </div>
            
            <!-- Pagination Controls -->
            <div id="pagination-controls" style="margin-top: 20px; display: none;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;">
                    <!-- Page Info and Size Selector -->
                    <div style="display: flex; align-items: center; gap: 15px; color: var(--text-light);">
                        <span id="pagination-info">Showing 1 to 10 of 100 devices</span>
                        <select id="page-size" style="padding: 8px; border-radius: 6px; border: 1px solid var(--border); background: var(--dark); color: var(--text);">
                            <option value="10">10</option>
                            <option value="25">25</option>
                            <option value="50">50</option>
                            <option value="100">100</option>
                        </select>
                    </div>
                    
                    <!-- Page Navigation -->
                    <div id="page-buttons" style="display: flex; gap: 5px; flex-wrap: wrap;">
                        <!-- Buttons will be generated here -->
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Edit Device Modal -->
    <div id="edit-modal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center;">
        <div style="background: var(--dark-light); border-radius: 15px; padding: 30px; width: 90%; max-width: 500px; box-shadow: 0 10px 40px rgba(0,0,0,0.5);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="color: var(--primary); margin: 0;">
                    <i class="fas fa-edit"></i> Cihaz Düzenle
                </h2>
                <button onclick="closeEditModal()" style="background: none; border: none; color: var(--text); font-size: 24px; cursor: pointer; padding: 0; width: 30px; height: 30px;">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <form id="edit-form">
                <input type="hidden" id="edit-device-id">
                <input type="hidden" id="edit-original-mac">
                
                <div class="form-group">
                    <label for="edit-ip-address">
                        <i class="fas fa-network-wired"></i> IP Address
                    </label>
                    <input type="text" id="edit-ip-address" placeholder="e.g., 192.0.2.10" required>
                </div>
                
                <div class="form-group">
                    <label for="edit-hostname">
                        <i class="fas fa-server"></i> Hostname
                    </label>
                    <input type="text" id="edit-hostname" placeholder="e.g., TEST-PC-01" required>
                </div>
                
                <div class="form-group">
                    <label for="edit-mac-address">
                        <i class="fas fa-ethernet"></i> MAC Address
                    </label>
                    <input type="text" id="edit-mac-address" placeholder="e.g., 00:11:22:33:44:55" required>
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 20px;">
                    <button type="button" onclick="closeEditModal()" class="btn" style="flex: 1; background: var(--border);">
                        <i class="fas fa-times"></i> İptal
                    </button>
                    <button type="submit" class="btn btn-success" style="flex: 1;">
                        <i class="fas fa-save"></i> Kaydet
                    </button>
                </div>
            </form>
            
            <div class="result-message" id="edit-result" style="margin-top: 15px;"></div>
        </div>
    </div>
    
    <script>
        function toggleSection(id) {
            const el = document.getElementById(id);
            if (!el) return;
            if (el.style.display === 'none' || el.style.display === '') {
                el.style.display = 'block';
                el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
                el.style.display = 'none';
            }
        }

        const uploadArea = document.getElementById('upload-area');
        const fileInput = document.getElementById('file-input');
        const progressBar = document.getElementById('progress-bar');
        const progressFill = document.getElementById('progress-fill');
        const resultMessage = document.getElementById('result-message');
        const manualForm = document.getElementById('manual-form');
        const manualResult = document.getElementById('manual-result');
        
        // Drag and drop handlers
        uploadArea.addEventListener('click', () => fileInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('drag-over');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('drag-over');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFile(files[0]);
            }
        });
        
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFile(e.target.files[0]);
            }
        });
        
        function handleFile(file) {
            const allowedTypes = ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'text/csv'];
            if (!allowedTypes.includes(file.type) && !file.name.match(/\.(xlsx|xls|csv)$/i)) {
                showResult('error', 'Invalid file type. Please upload an Excel or CSV file.');
                return;
            }
            
            uploadFile(file);
        }
        
        function uploadFile(file) {
            const formData = new FormData();
            formData.append('excel_file', file);
            
            progressBar.style.display = 'block';
            resultMessage.style.display = 'none';
            
            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressFill.style.width = percentComplete + '%';
                    progressFill.textContent = Math.round(percentComplete) + '%';
                }
            });
            
            xhr.addEventListener('load', () => {
                if (xhr.status === 200) {
                    try {
                        const response = JSON.parse(xhr.responseText);
                        if (response.success) {
                            let message = `Import completed successfully!<br>
                                Total Rows: ${response.total_rows}<br>
                                Success: ${response.success_count}<br>
                                Errors: ${response.error_count}`;
                            
                            showResult('success', message);
                            
                            if (response.errors && response.errors.length > 0) {
                                let errorHtml = '<div class="error-list"><h4>Errors:</h4>';
                                response.errors.forEach(err => {
                                    errorHtml += `<div class="error-item">${err}</div>`;
                                });
                                errorHtml += '</div>';
                                resultMessage.innerHTML += errorHtml;
                            }
                            
                            loadDevices();
                        } else {
                            showResult('error', response.error || 'Import failed');
                        }
                    } catch (e) {
                        showResult('error', 'Failed to parse response');
                    }
                } else {
                    showResult('error', 'Upload failed with status ' + xhr.status);
                }
                progressBar.style.display = 'none';
            });
            
            xhr.addEventListener('error', () => {
                showResult('error', 'Upload failed. Please check your connection.');
                progressBar.style.display = 'none';
            });
            
            xhr.open('POST', 'device_import_api.php');
            xhr.send(formData);
        }
        
        function showResult(type, message) {
            resultMessage.className = 'result-message ' + type;
            resultMessage.innerHTML = message;
            resultMessage.style.display = 'block';
        }
        
        function showManualResult(type, message) {
            manualResult.className = 'result-message ' + type;
            manualResult.innerHTML = message;
            manualResult.style.display = 'block';
            
            setTimeout(() => {
                manualResult.style.display = 'none';
            }, 5000);
        }
        
        // Manual form submission
        manualForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const ipAddress = document.getElementById('ip-address').value.trim();
            const hostname = document.getElementById('hostname').value.trim();
            const macAddress = document.getElementById('mac-address').value.trim();
            
            // Client-side validation with proper IP octet range check
            const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            if (!ipPattern.test(ipAddress)) {
                showManualResult('error', 'Invalid IP address format (each octet must be 0-255)');
                return;
            }
            
            if (!hostname) {
                showManualResult('error', 'Hostname is required');
                return;
            }
            
            if (!macAddress) {
                showManualResult('error', 'MAC address is required');
                return;
            }
            
            try {
                const response = await fetch('device_import_api.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        action: 'manual_add',
                        ip_address: ipAddress,
                        hostname: hostname,
                        mac_address: macAddress
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showManualResult('success', 'Device added successfully!');
                    manualForm.reset();
                    loadDevices();
                } else {
                    const errors = data.errors ? data.errors.join('<br>') : data.error;
                    showManualResult('error', errors);
                }
            } catch (error) {
                showManualResult('error', 'Error: ' + error.message);
            }
        });
        
        // Pagination and search state
        let currentPage = 1;
        let currentLimit = 10;
        let currentSearch = '';
        let searchTimeout = null;
        let applyMatchStatus = null; // { matched: Set, unmatched: Set } after apply_to_ports
        
        // Search functionality
        document.getElementById('device-search').addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            currentSearch = e.target.value.trim();
            
            const clearBtn = document.getElementById('clear-search');
            clearBtn.style.display = currentSearch ? 'block' : 'none';
            
            // Debounce search - wait 300ms after user stops typing
            searchTimeout = setTimeout(() => {
                currentPage = 1; // Reset to first page on new search
                loadDevices();
            }, 300);
        });
        
        document.getElementById('clear-search').addEventListener('click', () => {
            document.getElementById('device-search').value = '';
            document.getElementById('clear-search').style.display = 'none';
            currentSearch = '';
            currentPage = 1;
            loadDevices();
        });
        
        // Page size change
        document.getElementById('page-size').addEventListener('change', (e) => {
            currentLimit = parseInt(e.target.value);
            currentPage = 1; // Reset to first page
            loadDevices();
        });
        
        function loadDevices() {
            const params = new URLSearchParams({
                action: 'list',
                page: currentPage,
                limit: currentLimit
            });
            
            if (currentSearch) {
                params.append('search', currentSearch);
            }
            
            fetch('device_import_api.php?' + params.toString())
                .then(res => res.json())
                .then(data => {
                    if (data.success && data.devices) {
                        renderDeviceTable(data.devices);
                        renderPagination(data);
                    }
                })
                .catch(error => {
                    document.getElementById('device-list').innerHTML = 
                        '<p style="color: var(--danger);">Error loading devices</p>';
                });
        }
        
        function renderDeviceTable(devices) {
            if (devices.length === 0) {
                document.getElementById('device-list').innerHTML = 
                    '<p style="text-align: center; color: var(--text-light); padding: 40px;">No devices found</p>';
                return;
            }
            
            let html = `<table>
                <tr>
                    <th>MAC Address</th>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Source</th>
                    <th>Updated</th>
                    <th style="text-align: center;">Actions</th>
                </tr>`;
            
            devices.forEach(device => {
                let rowStyle = '';
                let matchBadge = '';
                if (applyMatchStatus) {
                    const mac = device.mac_address;
                    if (applyMatchStatus.matched.has(mac)) {
                        rowStyle = 'background: rgba(16,185,129,0.12);';
                        matchBadge = '<span style="margin-left:6px;padding:2px 7px;border-radius:10px;font-size:0.75em;background:#10b981;color:#fff;vertical-align:middle;">✓ Eşleşti</span>';
                    } else if (applyMatchStatus.unmatched.has(mac)) {
                        rowStyle = 'background: rgba(239,68,68,0.12);';
                        matchBadge = '<span style="margin-left:6px;padding:2px 7px;border-radius:10px;font-size:0.75em;background:#ef4444;color:#fff;vertical-align:middle;">✗ Eşleşmedi</span>';
                    }
                }
                html += `<tr style="${rowStyle}">
                    <td><code>${device.mac_address}</code>${matchBadge}</td>
                    <td>${device.ip_address || '-'}</td>
                    <td><strong>${device.device_name}</strong></td>
                    <td><span style="color: var(--${device.source === 'manual' ? 'success' : 'primary'});">${device.source}</span></td>
                    <td style="color: var(--text-light);">${new Date(device.updated_at).toLocaleString()}</td>
                    <td style="text-align: center;">
                        <button onclick='openEditModal(${JSON.stringify(device)})' class="btn btn-sm" style="padding: 5px 10px; background: var(--primary);">
                            <i class="fas fa-edit"></i> Düzenle
                        </button>
                    </td>
                </tr>`;
            });
            
            html += '</table>';
            document.getElementById('device-list').innerHTML = html;
        }
        
        function renderPagination(data) {
            const { page, limit, total, totalPages } = data;
            
            if (total === 0) {
                document.getElementById('pagination-controls').style.display = 'none';
                return;
            }
            
            document.getElementById('pagination-controls').style.display = 'block';
            
            // Update info text
            const start = (page - 1) * limit + 1;
            const end = Math.min(page * limit, total);
            const searchText = currentSearch ? ` (filtered)` : '';
            document.getElementById('pagination-info').textContent = 
                `Showing ${start} to ${end} of ${total} devices${searchText}`;
            
            // Update page size selector
            document.getElementById('page-size').value = limit;
            
            // Render page buttons
            let buttonsHtml = '';
            
            // Previous button
            if (page > 1) {
                buttonsHtml += `<button onclick="changePage(${page - 1})" class="btn btn-sm" style="padding: 8px 12px;">
                    <i class="fas fa-chevron-left"></i> Önceki
                </button>`;
            }
            
            // Page numbers
            const maxButtons = 5;
            let startPage = Math.max(1, page - Math.floor(maxButtons / 2));
            let endPage = Math.min(totalPages, startPage + maxButtons - 1);
            
            // Adjust if we're near the end
            if (endPage - startPage < maxButtons - 1) {
                startPage = Math.max(1, endPage - maxButtons + 1);
            }
            
            // First page + ellipsis
            if (startPage > 1) {
                buttonsHtml += `<button onclick="changePage(1)" class="btn btn-sm" style="padding: 8px 12px;">1</button>`;
                if (startPage > 2) {
                    buttonsHtml += `<span style="padding: 8px 12px; color: var(--text-light);">...</span>`;
                }
            }
            
            // Page number buttons
            for (let i = startPage; i <= endPage; i++) {
                const isActive = i === page;
                const style = isActive 
                    ? 'padding: 8px 12px; background: var(--primary); color: white; font-weight: bold;' 
                    : 'padding: 8px 12px;';
                buttonsHtml += `<button onclick="changePage(${i})" class="btn btn-sm" style="${style}">${i}</button>`;
            }
            
            // Ellipsis + last page
            if (endPage < totalPages) {
                if (endPage < totalPages - 1) {
                    buttonsHtml += `<span style="padding: 8px 12px; color: var(--text-light);">...</span>`;
                }
                buttonsHtml += `<button onclick="changePage(${totalPages})" class="btn btn-sm" style="padding: 8px 12px;">${totalPages}</button>`;
            }
            
            // Next button
            if (page < totalPages) {
                buttonsHtml += `<button onclick="changePage(${page + 1})" class="btn btn-sm" style="padding: 8px 12px;">
                    Sonraki <i class="fas fa-chevron-right"></i>
                </button>`;
            }
            
            document.getElementById('page-buttons').innerHTML = buttonsHtml;
        }
        
        function changePage(page) {
            currentPage = page;
            loadDevices();
        }
        
        function openEditModal(device) {
            document.getElementById('edit-device-id').value = device.id || '';
            document.getElementById('edit-original-mac').value = device.mac_address;
            document.getElementById('edit-ip-address').value = device.ip_address || '';
            document.getElementById('edit-hostname').value = device.device_name || '';
            document.getElementById('edit-mac-address').value = device.mac_address;
            document.getElementById('edit-result').innerHTML = '';
            
            const modal = document.getElementById('edit-modal');
            modal.style.display = 'flex';
        }
        
        function closeEditModal() {
            document.getElementById('edit-modal').style.display = 'none';
            document.getElementById('edit-form').reset();
        }
        
        // Edit form submission
        document.getElementById('edit-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const originalMac = document.getElementById('edit-original-mac').value;
            const ipAddress = document.getElementById('edit-ip-address').value;
            const hostname = document.getElementById('edit-hostname').value;
            const macAddress = document.getElementById('edit-mac-address').value;
            
            const resultDiv = document.getElementById('edit-result');
            resultDiv.innerHTML = '<p style="color: var(--warning);">Updating device...</p>';
            
            try {
                const response = await fetch('device_import_api.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        action: 'update',
                        original_mac: originalMac,
                        ip_address: ipAddress,
                        device_name: hostname,
                        mac_address: macAddress
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    resultDiv.innerHTML = `<p style="color: var(--success);">
                        <i class="fas fa-check-circle"></i> ${result.message || 'Device updated successfully!'}
                    </p>`;
                    
                    // Reload devices after successful update
                    setTimeout(() => {
                        closeEditModal();
                        loadDevices();
                    }, 1500);
                } else {
                    resultDiv.innerHTML = `<p style="color: var(--danger);">
                        <i class="fas fa-exclamation-circle"></i> Error: ${result.error || 'Update failed'}
                    </p>`;
                }
            } catch (error) {
                resultDiv.innerHTML = `<p style="color: var(--danger);">
                    <i class="fas fa-exclamation-circle"></i> Network error: ${error.message}
                </p>`;
            }
        });
        
        function downloadTemplate() {
            // Create a simple CSV template with RFC 5737 test addresses
            const csvContent = "IP Adresi,Hostname,MAC Adresi\n192.0.2.10,TEST-PC-01,00:11:22:33:44:55\n192.0.2.20,TEST-SW-02,AA:BB:CC:DD:EE:FF\n";
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement("a");
            const url = URL.createObjectURL(blob);
            link.setAttribute("href", url);
            link.setAttribute("download", "device_import_template.csv");
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        
        // Bulk apply Device Import data to all matching ports
        async function applyDeviceImportToPorts() {
            if (!confirm('Device Import verilerini tüm eşleşen portlara uygulamak istiyor musunuz?\n\nBu işlem, MAC adresi eşleşen tüm port bağlantılarının IP ve Hostname bilgilerini güncelleyecektir.')) {
                return;
            }
            
            const btn = document.getElementById('applyToPortsBtn');
            const originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uygulanıyor...';
            
            try {
                const response = await fetch('device_import_api.php?action=apply_to_ports', {
                    method: 'POST'
                });
                
                const data = await response.json();
                
                if (data.success) {
                    alert(`Başarılı! ${data.updated_count} port bağlantısı güncellendi.\n✓ Eşleşen: ${(data.matched_macs || []).length}  ✗ Eşleşmeyen: ${(data.unmatched_macs || []).length}`);
                    // Store match status for color-coding the table
                    applyMatchStatus = {
                        matched: new Set(data.matched_macs || []),
                        unmatched: new Set(data.unmatched_macs || [])
                    };
                    loadDevices();
                } else {
                    alert('Hata: ' + (data.error || 'Bilinmeyen hata'));
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Hata: ' + error.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = originalText;
            }
        }
        
        // Load devices on page load
        document.addEventListener('DOMContentLoaded', () => {
            loadDevices();
        });
    </script>
</body>
</html>
