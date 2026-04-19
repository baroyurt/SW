<?php
// Require authentication
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

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

        /* Toast notifications */
        #toast-container {
            position: fixed;
            bottom: 24px;
            right: 24px;
            z-index: 99999;
            display: flex;
            flex-direction: column;
            gap: 10px;
            pointer-events: none;
        }
        .toast {
            padding: 14px 20px;
            border-radius: 10px;
            color: white;
            font-size: 14px;
            font-weight: 500;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
            max-width: 380px;
            pointer-events: auto;
            animation: toastIn 0.3s ease;
        }
        .toast.success { background: rgba(16,185,129,0.95); border-left: 4px solid #059669; }
        .toast.error   { background: rgba(239,68,68,0.95);  border-left: 4px solid #dc2626; }
        .toast.info    { background: rgba(59,130,246,0.95);  border-left: 4px solid #2563eb; }
        @keyframes toastIn  { from { transform: translateX(110%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes toastOut { from { transform: translateX(0);    opacity: 1; } to { transform: translateX(110%); opacity: 0; } }

        /* Download password modal */
        .dl-modal {
            display: none;
            position: fixed; z-index: 10000;
            left: 0; top: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7);
            backdrop-filter: blur(5px);
            justify-content: center; align-items: center;
        }
        .dl-modal.show { display: flex; }
        .dl-modal-content {
            background: var(--dark-light);
            padding: 30px;
            border-radius: 15px;
            width: 90%; max-width: 420px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        .dl-modal-title {
            font-size: 17px; font-weight: bold; color: var(--text);
            margin-bottom: 12px; display: flex; align-items: center; gap: 10px;
        }
        .dl-modal-body { color: var(--text-light); font-size: 13px; margin-bottom: 18px; line-height: 1.5; }
        .dl-modal-input {
            width: 100%; padding: 9px 12px;
            background: var(--dark); border: 1px solid var(--border);
            border-radius: 8px; color: var(--text); font-size: 14px;
            box-sizing: border-box; margin-bottom: 6px;
        }
        .dl-modal-input:focus { outline: none; border-color: #0ea5e9; }
        .dl-modal-error { font-size: 12px; color: #f87171; display: none; margin-bottom: 16px; }
        .dl-modal-actions { display: flex; gap: 10px; justify-content: flex-end; }

        /* Confirm modal */
        .confirm-modal {
            display: none;
            position: fixed; z-index: 10000;
            left: 0; top: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7);
            backdrop-filter: blur(5px);
            justify-content: center; align-items: center;
        }
        .confirm-modal.show { display: flex; }
        .confirm-modal-content {
            background: var(--dark-light);
            padding: 30px;
            border-radius: 15px;
            width: 90%; max-width: 460px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        .confirm-modal-title {
            font-size: 18px; font-weight: bold; color: var(--text);
            margin-bottom: 15px; display: flex; align-items: center; gap: 10px;
        }
        .confirm-modal-body { color: var(--text-light); line-height: 1.6; margin-bottom: 24px; font-size: 14px; }
        .confirm-modal-actions { display: flex; gap: 10px; justify-content: flex-end; }
    </style>
</head>
<body>
    <div id="toast-container"></div>

    <!-- Download password modal -->
    <div id="dlPasswordModal" class="dl-modal">
        <div class="dl-modal-content">
            <div class="dl-modal-title"><i class="fas fa-lock" style="color:#0ea5e9;"></i> İndirme Onayı</div>
            <div class="dl-modal-body">Kayıtları indirmek için şifrenizi girin.</div>
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

    <!-- Confirm Modal -->
    <div id="confirmModal" class="confirm-modal">
        <div class="confirm-modal-content">
            <div class="confirm-modal-title"><i class="fas fa-question-circle" style="color:var(--warning);"></i> <span id="confirmTitle"></span></div>
            <div class="confirm-modal-body" id="confirmBody"></div>
            <div class="confirm-modal-actions">
                <button id="confirmCancel" style="padding:10px 20px;border:1px solid var(--border);background:transparent;color:var(--text-light);border-radius:8px;cursor:pointer;font-size:14px;">
                    <i class="fas fa-times"></i> İptal
                </button>
                <button id="confirmOk" style="padding:10px 20px;background:var(--success);color:white;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;">
                    <i class="fas fa-check"></i> Onayla
                </button>
            </div>
        </div>
    </div>
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
                <p style="margin-top:10px;color:var(--success);"><i class="fas fa-sync-alt"></i> <strong>MAC Eşleştirme:</strong> Sistemde kayıtlı bir MAC ile eşleşme bulunursa, Excel'deki IP Adresi ve Hostname otomatik olarak uygulanır. SNMP tarafından otomatik atanan değerlerin üzerine yazılır.</p>
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
                
                <!-- Sync & Scan Button -->
                <button id="syncScanBtn" onclick="syncAndScan()"
                        style="background: #7c3aed; color: white; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600;"
                        title="Kayıtlı cihazları portlara uygular, ardından kayıtsız MAC'leri tarayıp alarm oluşturur. Her saat otomatik çalışır.">
                    <i class="fas fa-sync-alt"></i> Senkronize Et &amp; Tara
                </button>

                <!-- Export XLSX Button -->
                <button onclick="openDlModal()" class="btn" 
                   style="background: #0ea5e9; color: white; padding: 10px 20px; border: none; cursor: pointer;"
                   title="Mevcut tüm cihaz kayıtlarını Excel (xlsx) formatında indirin">
                    <i class="fas fa-file-excel"></i> Kayıtları İndir (Excel)
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

            <!-- Status Filter Bar (visible only after Apply to Ports has run) -->
            <div id="status-filter-bar" style="display:none;margin-bottom:14px;gap:8px;flex-wrap:wrap;align-items:center;">
                <span style="color:var(--text-light);font-size:13px;margin-right:4px;">Filtre:</span>
                <button class="btn status-filter-btn active-filter" data-filter="all"
                        style="font-size:12px;padding:5px 12px;background:var(--primary);color:#fff;border:none;">
                    Tümü
                </button>
                <button class="btn status-filter-btn" data-filter="updated"
                        style="font-size:12px;padding:5px 12px;background:var(--dark-light);color:var(--text-light);border:1px solid var(--border);">
                    ✓ Güncellendi
                </button>
                <button class="btn status-filter-btn" data-filter="matched"
                        style="font-size:12px;padding:5px 12px;background:var(--dark-light);color:var(--text-light);border:1px solid var(--border);">
                    ✓ Eşleşti
                </button>
                <button class="btn status-filter-btn" data-filter="unmatched"
                        style="font-size:12px;padding:5px 12px;background:var(--dark-light);color:var(--text-light);border:1px solid var(--border);">
                    ✗ Eşleşmedi
                </button>
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
                    <button type="button" onclick="deleteDevice()" class="btn btn-danger" style="flex: 1;">
                        <i class="fas fa-trash"></i> Sil
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
                            let message = `İçe aktarma tamamlandı!<br>
                                Toplam Satır: ${response.total_rows}<br>
                                Güncellenen/Eklenen: ${response.success_count}<br>
                                Hatalı: ${response.error_count}<br>
                                <small style="color:var(--text-light);">Mevcut MAC adresleriyle eşleşenler Excel'deki IP ve Hostname ile güncellendi.</small>`;
                            
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
            
            xhr.open('POST', '../api/device_import_api.php');
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
                const response = await fetch('../api/device_import_api.php', {
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
        let currentStatusFilter = 'all'; // 'all' | 'updated' | 'matched' | 'unmatched'
        let searchTimeout = null;
        // { updated: Set, already_current: Set, unmatched: Set } – persisted in localStorage
        let applyMatchStatus = null;

        // Toast notification helper
        function showToast(message, type = 'info', duration = 4500) {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️';
            toast.textContent = icon + ' ' + message;
            container.appendChild(toast);
            setTimeout(() => {
                toast.style.animation = 'toastOut 0.3s ease forwards';
                setTimeout(() => toast.remove(), 310);
            }, duration);
        }

        // Confirm modal helper
        function showConfirm(title, body) {
            return new Promise(resolve => {
                document.getElementById('confirmTitle').textContent = title;
                document.getElementById('confirmBody').textContent = body;
                const modal = document.getElementById('confirmModal');
                modal.classList.add('show');
                const ok     = document.getElementById('confirmOk');
                const cancel = document.getElementById('confirmCancel');
                const cleanup = (result) => {
                    modal.classList.remove('show');
                    ok.removeEventListener('click', onOk);
                    cancel.removeEventListener('click', onCancel);
                    resolve(result);
                };
                const onOk     = () => cleanup(true);
                const onCancel = () => cleanup(false);
                ok.addEventListener('click', onOk);
                cancel.addEventListener('click', onCancel);
            });
        }

        // Restore persisted match status
        (function restoreMatchStatus() {
            try {
                const stored = localStorage.getItem('applyMatchStatus');
                if (stored) {
                    const p = JSON.parse(stored);
                    applyMatchStatus = {
                        updated:         new Set(p.updated         || []),
                        already_current: new Set(p.already_current || []),
                        unmatched:       new Set(p.unmatched       || [])
                    };
                    showStatusFilterBar();
                }
            } catch (e) { console.error('Failed to restore match status:', e); }
        })();

        function showStatusFilterBar() {
            const bar = document.getElementById('status-filter-bar');
            if (bar) bar.style.display = 'flex';
        }

        // Status filter button clicks
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('.status-filter-btn');
            if (!btn) return;
            currentStatusFilter = btn.dataset.filter;
            currentPage = 1;
            // Update active button styles
            document.querySelectorAll('.status-filter-btn').forEach(b => {
                if (b === btn) {
                    b.style.background = 'var(--primary)';
                    b.style.color = '#fff';
                    b.style.border = 'none';
                } else {
                    b.style.background = 'var(--dark-light)';
                    b.style.color = 'var(--text-light)';
                    b.style.border = '1px solid var(--border)';
                }
            });
            loadDevices();
        });
        
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
            // Build the request URL with simple GET params.
            // Status filtering now uses the server-side match_status column
            // (set by apply_to_ports) instead of sending large MAC arrays.
            const params = new URLSearchParams({
                action: 'list',
                page: currentPage,
                limit: currentLimit
            });
            if (currentSearch) params.append('search', currentSearch);

            if (currentStatusFilter !== 'all') {
                // Map UI filter names to DB status values
                const statusMap = {
                    updated:   'updated',
                    matched:   'already_current',
                    unmatched: 'unmatched'
                };
                const dbStatus = statusMap[currentStatusFilter];
                if (dbStatus) params.append('status_filter', dbStatus);
            }

            fetch('../api/device_import_api.php?' + params.toString())
                .then(res => res.json())
                .then(data => {
                    if (data.success && data.devices !== undefined) {
                        renderDeviceTable(data.devices);
                        renderPagination(data);
                    } else {
                        document.getElementById('device-list').innerHTML =
                            '<p style="color: var(--danger);">Error loading devices: ' +
                            (data.error || 'Unknown error') + '</p>';
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
                    if (applyMatchStatus.updated.has(mac)) {
                        rowStyle = 'background: rgba(16,185,129,0.12);';
                        matchBadge = '<span style="margin-left:6px;padding:2px 7px;border-radius:10px;font-size:0.75em;background:#10b981;color:#fff;vertical-align:middle;">✓ Güncellendi</span>';
                    } else if (applyMatchStatus.already_current.has(mac)) {
                        rowStyle = 'background: rgba(59,130,246,0.10);';
                        matchBadge = '<span style="margin-left:6px;padding:2px 7px;border-radius:10px;font-size:0.75em;background:#3b82f6;color:#fff;vertical-align:middle;">✓ Eşleşti</span>';
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
            const filterLabels = { all: '', updated: ' (✓ Güncellendi)', matched: ' (✓ Eşleşti)', unmatched: ' (✗ Eşleşmedi)' };
            const filterText = (currentSearch ? ' (filtered)' : '') + (filterLabels[currentStatusFilter] || '');
            document.getElementById('pagination-info').textContent = 
                `Showing ${start} to ${end} of ${total} devices${filterText}`;
            
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

        async function deleteDevice() {
            const mac = document.getElementById('edit-original-mac').value;
            if (!mac) return;
            if (!confirm('Bu cihazı silmek istediğinizden emin misiniz?')) return;
            const resultDiv = document.getElementById('edit-result');
            resultDiv.innerHTML = '<p style="color: var(--warning);">Siliniyor...</p>';
            try {
                const response = await fetch('../api/device_import_api.php?_method=DELETE&mac=' + encodeURIComponent(mac), {
                    method: 'POST'
                });
                const result = await response.json();
                if (result.success) {
                    closeEditModal();
                    loadDevices();
                } else {
                    resultDiv.innerHTML = '<p style="color: var(--danger);">' + (result.error || 'Silme başarısız') + '</p>';
                }
            } catch (e) {
                resultDiv.innerHTML = '<p style="color: var(--danger);">Hata: ' + e.message + '</p>';
            }
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
                const response = await fetch('../api/device_import_api.php', {
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
        
        // Load devices on page load
        document.addEventListener('DOMContentLoaded', () => {
            loadDevices();
            // Run automatically if an hour or more has passed since last auto-sync
            _maybeAutoSync();
        });

        // ── Combined Sync & Scan ─────────────────────────────────────────────
        // Runs apply_to_ports then scan_unregistered in one server call.

        async function _runSyncAndScan(silent = false) {
            const response = await fetch('../api/device_import_api.php?action=sync_and_scan', { method: 'POST' });
            const data = await response.json();
            if (!data.success) throw new Error(data.error || 'Bilinmeyen hata');

            // Update match-status filter state
            applyMatchStatus = {
                updated:         new Set(data.updated_macs         || []),
                already_current: new Set(data.already_current_macs || []),
                unmatched:       new Set(data.unmatched_macs       || [])
            };
            try {
                localStorage.setItem('applyMatchStatus', JSON.stringify({
                    updated:         [...applyMatchStatus.updated],
                    already_current: [...applyMatchStatus.already_current],
                    unmatched:       [...applyMatchStatus.unmatched]
                }));
            } catch (e) {}

            if ((data.updated_count || 0) > 0 || (data.matched_macs || []).length > 0) {
                showStatusFilterBar();
                loadDevices();
            }

            if (!silent) {
                const updCnt  = (data.updated_macs         || []).length;
                const curCnt  = (data.already_current_macs || []).length;
                const unCnt   = (data.unmatched_macs       || []).length;
                const created = data.alarms_created   || 0;
                const skipped = data.alarms_skipped    || 0;
                const total   = data.total_unregistered || 0;
                const portsUpd = data.ports_updated    || 0;

                let msg = `Senkronizasyon tamamlandı! ${data.updated_count || 0} port güncellendi. `;
                msg += `✓ Güncellendi: ${updCnt}  ✓ Eşleşti: ${curCnt}  ✗ Eşleşmedi: ${unCnt}. `;
                if (total === 0 && created === 0) {
                    msg += 'Tüm aktif MAC\'ler kayıtlı, yeni alarm yok.';
                } else {
                    msg += `${total} kayıtsız MAC bulundu, ${created} yeni alarm`;
                    if (skipped > 0) msg += `, ${skipped} mevcut alarm atlandı`;
                    if (portsUpd > 0) msg += `, ${portsUpd} port IP ile güncellendi`;
                    msg += '.';
                }
                showToast(msg, created > 0 ? 'warning' : 'success', 8000);
            }
            return data;
        }

        async function syncAndScan() {
            const ok = await showConfirm(
                'Senkronize Et & Tara',
                'Kayıtlı cihazlar portlara uygulanacak, ardından kayıtsız MAC adresleri için alarm oluşturulacak. Devam etmek istiyor musunuz?'
            );
            if (!ok) return;

            const btn = document.getElementById('syncScanBtn');
            const originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Çalışıyor...';
            try {
                await _runSyncAndScan(false);
            } catch (error) {
                console.error('Sync & Scan error:', error);
                showToast('Hata: ' + error.message, 'error');
            } finally {
                btn.disabled = false;
                btn.innerHTML = originalText;
            }
        }

        // ── Hourly auto-run ──────────────────────────────────────────────────
        const AUTO_SYNC_INTERVAL_MS = 3600000; // 1 hour
        const AUTO_SYNC_KEY = 'lastAutoSync';

        async function _maybeAutoSync() {
            if (document.hidden) return;
            const last = parseInt(localStorage.getItem(AUTO_SYNC_KEY) || '0', 10);
            if (Date.now() - last < AUTO_SYNC_INTERVAL_MS) return;
            try {
                await _runSyncAndScan(true);
                localStorage.setItem(AUTO_SYNC_KEY, String(Date.now()));
            } catch (e) {
                console.debug('Hourly auto-sync failed silently:', e.message);
            }
        }

        // Check every minute whether the hour has elapsed
        setInterval(_maybeAutoSync, 60000);

        // ── Legacy individual functions kept for backwards-compatibility ─────
        // (in case any bookmark / external script still calls them)
        async function applyDeviceImportToPorts() { return syncAndScan(); }
        async function scanUnregisteredMacs()      { return syncAndScan(); }

        // ── Download password modal ──────────────────────────────────────────
        function openDlModal() {
            document.getElementById('dlPassword').value = '';
            document.getElementById('dlPasswordError').style.display = 'none';
            document.getElementById('dlPasswordModal').classList.add('show');
            setTimeout(function() { document.getElementById('dlPassword').focus(); }, 50);
        }

        function closeDlModal() {
            document.getElementById('dlPasswordModal').classList.remove('show');
            document.getElementById('dlPassword').value = '';
            document.getElementById('dlPasswordError').style.display = 'none';
        }

        document.getElementById('dlPasswordModal').addEventListener('click', function(e) {
            if (e.target === this) closeDlModal();
        });

        document.getElementById('dlPassword').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') confirmDownload();
        });

        async function confirmDownload() {
            const password = document.getElementById('dlPassword').value;
            const errEl   = document.getElementById('dlPasswordError');
            const btn     = document.getElementById('dlConfirmBtn');

            if (!password) {
                errEl.textContent = 'Şifre boş olamaz.';
                errEl.style.display = 'block';
                document.getElementById('dlPassword').focus();
                return;
            }

            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Doğrulanıyor…';
            errEl.style.display = 'none';

            try {
                const res  = await fetch('../api/verify_password_api.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();

                if (!data.success) {
                    errEl.textContent = data.message || 'Şifre hatalı.';
                    errEl.style.display = 'block';
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-file-excel"></i> İndir';
                    document.getElementById('dlPassword').focus();
                    document.getElementById('dlPassword').select();
                    return;
                }

                // Password verified — trigger the file download
                closeDlModal();
                window.location.href = '../api/device_import_api.php?action=export_xlsx';
            } catch (e) {
                errEl.textContent = 'Sunucu hatası. Lütfen tekrar deneyin.';
                errEl.style.display = 'block';
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-file-excel"></i> İndir';
            }
        }
    </script>
</body>
</html>
