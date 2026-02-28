<?php
// Admin Dashboard - Comprehensive Management Interface
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

$currentUser = $auth->getUser();

// Check if user is admin
if ($currentUser['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}

// Prevent caching
header("Cache-Control: no-cache, no-store, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Yönetim Paneli</title>
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
            color: var(--text);
            min-height: 100vh;
        }
        
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 280px;
            height: 100vh;
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(10px);
            border-right: 1px solid rgba(56, 189, 248, 0.2);
            overflow-y: auto;
            z-index: 1000;
        }
        
        .logo-section {
            padding: 25px 20px;
            border-bottom: 1px solid rgba(56, 189, 248, 0.2);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .logo-section i {
            font-size: 2rem;
            color: var(--primary);
        }

        .logo-section h1 {
            color: var(--text);
            font-size: 1.3rem;
            margin-bottom: 3px;
        }
        
        .logo-section p {
            color: var(--text-light);
            font-size: 12px;
        }

        /* Monitor return button */
        .monitor-btn {
            position: fixed;
            right: 30px;
            bottom: 30px;
            z-index: 101;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            border: none;
            color: white;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
            box-shadow: 0 5px 20px rgba(16, 185, 129, 0.4);
            font-size: 1.5rem;
            text-decoration: none;
        }
        .monitor-btn:hover {
            transform: scale(1.15);
            box-shadow: 0 8px 30px rgba(16, 185, 129, 0.6);
        }
        
        .nav-section {
            padding: 15px 0;
            border-bottom: 1px solid var(--border);
        }
        
        .nav-title {
            padding: 10px 20px;
            color: var(--text-light);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 12px 20px;
            color: var(--text);
            cursor: pointer;
            transition: all 0.3s;
            border: none;
            background: none;
            width: 100%;
            text-align: left;
        }
        
        .nav-item:hover {
            background: rgba(56, 189, 248, 0.1);
            color: var(--text);
            transform: translateX(5px);
            padding-left: 20px;
        }
        
        .nav-item.active {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            box-shadow: 0 5px 20px rgba(59, 130, 246, 0.4);
        }
        
        .nav-item i {
            width: 20px;
            text-align: center;
        }
        
        .main-content {
            margin-left: 280px;
            padding: 30px;
        }
        
        .top-bar {
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            padding: 20px 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid rgba(56, 189, 248, 0.3);
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .page-title {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .page-title h2 {
            color: var(--primary);
            font-size: 28px;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--primary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        
        .content-section {
            display: none;
        }
        
        .content-section.active {
            display: block;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.8) 100%);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(56, 189, 248, 0.3);
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(56, 189, 248, 0.3);
        }
        
        .stat-icon {
            font-size: 32px;
            margin-bottom: 15px;
        }
        
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: var(--text-light);
            font-size: 14px;
        }
        
        .card {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.8) 100%);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(56, 189, 248, 0.3);
            margin-bottom: 20px;
        }
        
        .card h3 {
            color: var(--primary);
            margin-bottom: 20px;
            font-size: 20px;
        }
        
        .btn {
            padding: 12px 24px;
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
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-danger:hover {
            background: #dc2626;
        }

        .btn-warning-ghost {
            background: rgba(251,146,60,0.12);
            color: #fb923c;
            border: 1px solid rgba(251,146,60,0.3);
        }
        .btn-warning-ghost:hover {
            background: rgba(251,146,60,0.22);
        }
        
        .actions-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .action-btn {
            padding: 20px;
            background: var(--dark);
            border: 1px solid var(--border);
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s;
            text-align: center;
        }
        
        .action-btn:hover {
            background: rgba(59, 130, 246, 0.1);
            border-color: var(--primary);
            transform: translateY(-3px);
        }
        
        .action-btn i {
            font-size: 32px;
            color: var(--primary);
            margin-bottom: 10px;
        }
        
        .action-btn span {
            display: block;
            color: var(--text);
            font-weight: 600;
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
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.95) 100%);
            backdrop-filter: blur(20px);
            border-radius: 15px;
            padding: 30px;
            max-width: 600px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            border: 1px solid rgba(56, 189, 248, 0.3);
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .modal-title {
            color: var(--primary);
            font-size: 24px;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text);
            font-size: 28px;
            cursor: pointer;
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
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: rgba(15, 23, 42, 0.8);
            color: var(--text);
            font-size: 16px;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2), 0 0 15px rgba(56, 189, 248, 0.2);
        }
        
        .toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            padding: 15px 25px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 10000;
            animation: slideIn 0.3s;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .toast.success { background: var(--success); }
        .toast.error { background: var(--danger); }
        .toast.info { background: var(--primary); }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo-section">
            <i class="fas fa-cogs"></i>
            <div>
                <h1>Admin Panel</h1>
                <p>Yönetim ve Kontrol Merkezi</p>
            </div>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Ana Menü</div>
            <button class="nav-item active" data-page="dashboard">
                <i class="fas fa-tachometer-alt"></i>
                <span>Dashboard</span>
            </button>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Yönetim</div>
            <button class="nav-item" data-page="switches">
                <i class="fas fa-network-wired"></i>
                <span>Switch Yönetimi</span>
            </button>
            <button class="nav-item" data-page="racks">
                <i class="fas fa-server"></i>
                <span>Rack Yönetimi</span>
            </button>
            <button class="nav-item" data-page="panels">
                <i class="fas fa-th-large"></i>
                <span>Panel Yönetimi</span>
            </button>
            <button class="nav-item" data-page="ports">
                <i class="fas fa-plug"></i>
                <span>Port Yönetimi</span>
            </button>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Veri İşlemleri</div>
            <button class="nav-item" data-page="backup">
                <i class="fas fa-database"></i>
                <span>Yedekleme</span>
            </button>
            <button class="nav-item" data-page="export">
                <i class="fas fa-file-export"></i>
                <span>Excel Export</span>
            </button>
            <button class="nav-item" onclick="openExcelImportModal()">
                <i class="fas fa-file-import"></i>
                <span>Excel İçe Aktarma</span>
            </button>
            <button class="nav-item" data-page="history">
                <i class="fas fa-history"></i>
                <span>Geçmiş Yedekler</span>
            </button>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">SNMP</div>
            <button class="nav-item" data-page="snmp">
                <i class="fas fa-sync-alt"></i>
                <span>SNMP Senkronizasyon</span>
            </button>
            <button class="nav-item" data-page="snmp-config">
                <i class="fas fa-cog"></i>
                <span>SNMP Konfigürasyon</span>
            </button>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Kullanıcı</div>
            <button class="nav-item" onclick="window.location.href='index.php'">
                <i class="fas fa-home"></i>
                <span>Ana Sayfa</span>
            </button>
            <button class="nav-item" onclick="window.location.href='logout.php'" style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid var(--danger);">
                <i class="fas fa-sign-out-alt"></i>
                <span>Çıkış Yap</span>
            </button>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Bar -->
        <div class="top-bar">
            <div class="page-title">
                <h2 id="page-title-text">Dashboard</h2>
            </div>
            <div class="user-info">
                <div class="user-avatar">
                    <?php echo strtoupper(substr($currentUser['full_name'], 0, 1)); ?>
                </div>
                <div>
                    <div style="font-weight: 600;"><?php echo htmlspecialchars($currentUser['full_name']); ?></div>
                    <div style="font-size: 12px; color: var(--text-light);">Administrator</div>
                </div>
            </div>
        </div>
        
        <!-- Dashboard Section -->
        <div class="content-section active" id="section-dashboard">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon" style="color: var(--primary);">
                        <i class="fas fa-network-wired"></i>
                    </div>
                    <div class="stat-value" id="stat-switches">0</div>
                    <div class="stat-label">Toplam Switch</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon" style="color: var(--success);">
                        <i class="fas fa-server"></i>
                    </div>
                    <div class="stat-value" id="stat-racks">0</div>
                    <div class="stat-label">Rack Kabin</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon" style="color: var(--warning);">
                        <i class="fas fa-th-large"></i>
                    </div>
                    <div class="stat-value" id="stat-panels">0</div>
                    <div class="stat-label">Patch Panel</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon" style="color: var(--danger);">
                        <i class="fas fa-plug"></i>
                    </div>
                    <div class="stat-value" id="stat-ports">0</div>
                    <div class="stat-label">Aktif Port</div>
                </div>
            </div>
            
            <div class="card">
                <h3><i class="fas fa-tasks"></i> Hızlı İşlemler</h3>
                <div class="actions-grid">
                    <div class="action-btn" onclick="switchPage('switches')">
                        <i class="fas fa-plus-circle"></i>
                        <span>Yeni Switch</span>
                    </div>
                    <div class="action-btn" onclick="switchPage('racks')">
                        <i class="fas fa-cube"></i>
                        <span>Yeni Rack</span>
                    </div>
                    <div class="action-btn" onclick="switchPage('panels')">
                        <i class="fas fa-th-large"></i>
                        <span>Yeni Patch Panel</span>
                    </div>
                    <div class="action-btn" onclick="switchPage('backup')">
                        <i class="fas fa-database"></i>
                        <span>Yedekle</span>
                    </div>
                    <div class="action-btn" onclick="switchPage('export')">
                        <i class="fas fa-file-export"></i>
                        <span>Excel Export</span>
                    </div>
                    <div class="action-btn" onclick="switchPage('snmp')">
                        <i class="fas fa-sync-alt"></i>
                        <span>SNMP Sync</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Switch Management Section -->
        <div class="content-section" id="section-switches">
            <div class="card">
                <h3><i class="fas fa-network-wired"></i> Switch Yönetimi</h3>
                <button class="btn btn-primary" onclick="openAdminSwitchModal()">
                    <i class="fas fa-plus"></i> Yeni Switch Ekle
                </button>
                <div id="switches-list" style="margin-top: 20px;">
                    <p style="color: var(--text-light);">Yükleniyor...</p>
                </div>
            </div>
        </div>
        
        <!-- Rack Management Section -->
        <div class="content-section" id="section-racks">
            <div class="card">
                <h3><i class="fas fa-server"></i> Rack Yönetimi</h3>
                <button class="btn btn-primary" onclick="openAdminRackModal()">
                    <i class="fas fa-plus"></i> Yeni Rack Ekle
                </button>
                <div id="racks-list" style="margin-top: 20px;">
                    <p style="color: var(--text-light);">Yükleniyor...</p>
                </div>
            </div>
        </div>
        
        <!-- Panel Management Section -->
        <div class="content-section" id="section-panels">
            <div class="card">
                <h3><i class="fas fa-th-large"></i> Panel Yönetimi</h3>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <button class="btn btn-primary" onclick="openAdminPatchPanelModal()">
                        <i class="fas fa-plus"></i> Patch Panel Ekle
                    </button>
                    <button class="btn btn-success" onclick="openAdminFiberPanelModal()">
                        <i class="fas fa-satellite-dish"></i> Fiber Panel Ekle
                    </button>
                </div>
                <div id="panels-list" style="margin-top: 20px;">
                    <p style="color: var(--text-light);">Yükleniyor...</p>
                </div>
            </div>
        </div>

        <!-- Port Management Section -->
        <div class="content-section" id="section-ports">
            <div class="card">
                <h3><i class="fas fa-plug"></i> Port Yönetimi</h3>
                <div style="display: flex; gap: 15px; align-items: center; flex-wrap: wrap; margin-bottom: 20px;">
                    <div>
                        <label style="color: var(--text-light); font-size: 14px; display: block; margin-bottom: 5px;">Switch Seçin</label>
                        <select id="admin-switch-select" onchange="loadAdminPorts()" style="padding: 10px 15px; border: 1px solid var(--border); border-radius: 8px; background: var(--dark); color: var(--text); font-size: 14px; min-width: 250px;">
                            <option value="">-- Switch Seçin --</option>
                        </select>
                    </div>
                    <div style="display: flex; gap: 10px; margin-top: 20px;">
                        <button class="btn btn-primary" onclick="adminVlanSync()" id="admin-vlan-btn" disabled>
                            <i class="fas fa-sync-alt"></i> VLAN Yenile
                        </button>
                        <button class="btn btn-danger" onclick="adminResetAllPorts()" id="admin-reset-btn" disabled>
                            <i class="fas fa-redo"></i> Tüm Portları Boşa Çek
                        </button>
                        <button class="btn btn-warning-ghost" onclick="cleanupPhantomPorts()" title="Port sayısı küçüldüğünde (örn: 84→52) fazla port satırlarını siler">
                            <i class="fas fa-broom"></i> Fantom Portları Temizle
                        </button>
                    </div>
                </div>
                <!-- Switch info bar (shown when switch selected) -->
                <div id="admin-switch-info" style="display:none; background:rgba(56,189,248,0.05); border:1px solid rgba(56,189,248,0.2); border-radius:8px; padding:12px 16px; margin-bottom:16px; display:none;">
                    <div style="display:flex; gap:24px; flex-wrap:wrap; align-items:center;">
                        <div><span style="color:var(--text-light); font-size:12px;">Switch</span><div id="info-sw-name" style="font-weight:700; color:var(--text);"></div></div>
                        <div><span style="color:var(--text-light); font-size:12px;">IP Adresi</span><div id="info-sw-ip" style="font-weight:600; color:#38bdf8;"></div></div>
                        <div><span style="color:var(--text-light); font-size:12px;">Marka/Model</span><div id="info-sw-model" style="color:var(--text-light);"></div></div>
                        <div><span style="color:var(--text-light); font-size:12px;">Port Sayısı</span><div id="info-sw-ports" style="color:var(--text);"></div></div>
                        <div><span style="color:var(--text-light); font-size:12px;">Rack</span><div id="info-sw-rack" style="color:var(--text);"></div></div>
                    </div>
                </div>
                <div id="admin-ports-grid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px;">
                    <p style="color: var(--text-light);">Yukarıdan switch seçin.</p>
                </div>
            </div>
        </div>
        
        <!-- Backup Section -->
        <div class="content-section" id="section-backup">
            <div class="card">
                <h3><i class="fas fa-database"></i> Yedekleme</h3>
                <button class="btn btn-success" onclick="createBackup()">
                    <i class="fas fa-save"></i> Yeni Yedek Oluştur
                </button>
                <div id="backup-status" style="margin-top: 20px;"></div>
            </div>
        </div>
        
        <!-- Export Section -->
        <div class="content-section" id="section-export">
            <div class="card">
                <h3><i class="fas fa-file-export"></i> Excel Export</h3>
                <div class="actions-grid" style="margin-top: 20px;">
                    <div class="action-btn" onclick="exportData('switches')">
                        <i class="fas fa-network-wired"></i>
                        <span>Switch Verisi</span>
                    </div>
                    <div class="action-btn" onclick="exportData('racks')">
                        <i class="fas fa-server"></i>
                        <span>Rack Verisi</span>
                    </div>
                    <div class="action-btn" onclick="exportData('panels')">
                        <i class="fas fa-th-large"></i>
                        <span>Panel Verisi</span>
                    </div>
                    <div class="action-btn" onclick="exportData('all')">
                        <i class="fas fa-database"></i>
                        <span>Tüm Veri</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- History Section -->
        <div class="content-section" id="section-history">
            <div class="card">
                <h3><i class="fas fa-history"></i> Geçmiş Yedekler</h3>
                <div id="backups-list"></div>
            </div>
        </div>
        
        <!-- SNMP Section -->
        <div class="content-section" id="section-snmp">
            <div class="card">
                <h3><i class="fas fa-sync-alt"></i> SNMP Veri Senkronizasyonu</h3>
                <button class="btn btn-primary" onclick="syncSNMP()">
                    <i class="fas fa-sync"></i> SNMP Verilerini Senkronize Et
                </button>
                <div id="snmp-status" style="margin-top: 20px;"></div>
            </div>
        </div>
        
        <!-- SNMP Configuration Section -->
        <div class="content-section" id="section-snmp-config">
            <div class="card" style="padding: 0; overflow: hidden;">
                <div style="padding: 20px; border-bottom: 1px solid var(--border);">
                    <h3><i class="fas fa-cog"></i> SNMP Konfigürasyon</h3>
                    <p style="color: var(--text-light); margin-top: 10px; margin-bottom: 0;">
                        SNMP yapılandırma ayarlarını, switch'leri, bildirim ayarlarını ve alarm seviyelerini yönetin.
                    </p>
                </div>
                <iframe 
                    src="admin_snmp_config.php" 
                    style="width: 100%; height: calc(100vh - 200px); border: none; display: block;"
                    frameborder="0"
                    id="snmp-config-iframe">
                </iframe>
            </div>
        </div>
    </div>
    
    <script>
        // Navigation
        function switchPage(pageName) {
            // Update navigation
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            document.querySelector(`[data-page="${pageName}"]`)?.classList.add('active');
            
            // Update content
            document.querySelectorAll('.content-section').forEach(section => {
                section.classList.remove('active');
            });
            document.getElementById(`section-${pageName}`)?.classList.add('active');
            
            // Update page title
            const titles = {
                'dashboard': 'Dashboard',
                'switches': 'Switch Yönetimi',
                'racks': 'Rack Yönetimi',
                'panels': 'Panel Yönetimi',
                'ports': 'Port Yönetimi',
                'backup': 'Yedekleme',
                'export': 'Excel Export',
                'history': 'Geçmiş Yedekler',
                'snmp': 'SNMP Senkronizasyon',
                'snmp-config': 'SNMP Konfigürasyon'
            };
            document.getElementById('page-title-text').textContent = titles[pageName] || 'Admin Panel';
        }
        
        // Setup navigation
        document.querySelectorAll('.nav-item[data-page]').forEach(item => {
            item.addEventListener('click', () => {
                const page = item.getAttribute('data-page');
                switchPage(page);
            });
        });
        
        // Load dashboard stats
        async function loadStats() {
            try {
                const response = await fetch('getData.php');
                const data = await response.json();
                
                if (data.switches) {
                    document.getElementById('stat-switches').textContent = data.switches.length;
                }
                if (data.racks) {
                    document.getElementById('stat-racks').textContent = data.racks.length;
                }
                if (data.patchPanels) {
                    document.getElementById('stat-panels').textContent = data.patchPanels.length;
                }
                
                // Count active ports
                let activePorts = 0;
                if (data.ports) {
                    // ports is an object with switch IDs as keys
                    Object.values(data.ports).forEach(switchPorts => {
                        if (Array.isArray(switchPorts)) {
                            activePorts += switchPorts.filter(p => p.connected_device || p.panel_port_id).length;
                        }
                    });
                }
                document.getElementById('stat-ports').textContent = activePorts;
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }
        
        // Backup functions
        async function createBackup() {
            const statusDiv = document.getElementById('backup-status');
            statusDiv.innerHTML = '<p style="color: var(--primary);"><i class="fas fa-spinner fa-spin"></i> Yedek oluşturuluyor...</p>';
            
            try {
                const response = await fetch('backup.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'action=backup'
                });
                
                const data = await response.json();
                
                if (data.success) {
                    statusDiv.innerHTML = `<p style="color: var(--success);"><i class="fas fa-check-circle"></i> ${data.message}</p>`;
                    showToast('Yedekleme başarılı!', 'success');
                } else {
                    statusDiv.innerHTML = `<p style="color: var(--danger);"><i class="fas fa-exclamation-circle"></i> ${data.error}</p>`;
                    showToast('Yedekleme başarısız!', 'error');
                }
            } catch (error) {
                statusDiv.innerHTML = `<p style="color: var(--danger);"><i class="fas fa-exclamation-circle"></i> Hata: ${error.message}</p>`;
                showToast('Bir hata oluştu!', 'error');
            }
        }
        
        // Export functions
        function exportData(type) {
            const url = `getData.php?export=${type}`;
            window.open(url, '_blank');
            showToast(`${type} verileri indiriliyor...`, 'info');
        }
        
        // SNMP sync
        async function syncSNMP() {
            const statusDiv = document.getElementById('snmp-status');
            statusDiv.innerHTML = '<p style="color: var(--primary);"><i class="fas fa-spinner fa-spin"></i> SNMP verileri senkronize ediliyor...</p>';
            
            try {
                const response = await fetch('snmp_data_api.php?action=sync_to_switches');
                const data = await response.json();
                
                if (data.success) {
                    statusDiv.innerHTML = `<p style="color: var(--success);"><i class="fas fa-check-circle"></i> ${data.message}</p>`;
                    showToast('SNMP senkronizasyonu başarılı!', 'success');
                    loadStats();
                } else {
                    statusDiv.innerHTML = `<p style="color: var(--danger);"><i class="fas fa-exclamation-circle"></i> ${data.error || 'Senkronizasyon başarısız'}</p>`;
                    showToast('SNMP senkronizasyonu başarısız!', 'error');
                }
            } catch (error) {
                statusDiv.innerHTML = `<p style="color: var(--danger);"><i class="fas fa-exclamation-circle"></i> Hata: ${error.message}</p>`;
                showToast('Bir hata oluştu!', 'error');
            }
        }
        
        // Toast notification
        function showToast(message, type = 'info') {
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.textContent = message;
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.remove();
            }, 3000);
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            loadStats();
            loadAdminData();
            // Check hash nav
            const hash = window.location.hash.replace('#','');
            if (hash) switchPage(hash);

            // ─── FORM SUBMIT LISTENERS (must be inside DOMContentLoaded; modal HTML is after the script tag) ───
            document.getElementById('adm-sw-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const id = document.getElementById('adm-sw-id').value;
                const payload = {
                    name: document.getElementById('adm-sw-name').value,
                    brand: document.getElementById('adm-sw-brand').value,
                    model: document.getElementById('adm-sw-model').value,
                    ports: document.getElementById('adm-sw-ports').value,
                    status: document.getElementById('adm-sw-status').value,
                    ip: document.getElementById('adm-sw-ip').value,
                    rackId: document.getElementById('adm-sw-rack').value
                };
                if (id) payload.id = id;
                try {
                    const r = await fetch('saveSwitch.php', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
                    const d = await r.json();
                    if (d.success||d.id) {
                        showToast(id ? 'Switch güncellendi' : 'Switch eklendi','success');
                        document.getElementById('adm-sw-modal').classList.remove('active');
                        loadStats(); loadAdminData();
                    } else showToast(d.error||'Kaydedilemedi','error');
                } catch(e) { showToast('Hata: '+e.message,'error'); }
            });

            document.getElementById('adm-rack-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const id = document.getElementById('adm-rack-id').value;
                const payload = {
                    name: document.getElementById('adm-rack-name').value,
                    location: document.getElementById('adm-rack-location').value,
                    slots: document.getElementById('adm-rack-slots').value,
                    description: document.getElementById('adm-rack-desc').value
                };
                if (id) payload.id = id;
                try {
                    const r = await fetch('saveRack.php', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
                    const d = await r.json();
                    if (d.success||d.id) {
                        showToast(id ? 'Rack güncellendi' : 'Rack eklendi','success');
                        document.getElementById('adm-rack-modal').classList.remove('active');
                        loadStats(); loadAdminData();
                    } else showToast(d.error||'Kaydedilemedi','error');
                } catch(e) { showToast('Hata: '+e.message,'error'); }
            });

            document.getElementById('adm-pp-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const payload = {
                    rackId: document.getElementById('adm-pp-rack').value,
                    panelLetter: document.getElementById('adm-pp-letter').value,
                    totalPorts: document.getElementById('adm-pp-ports').value,
                    positionInRack: document.getElementById('adm-pp-slot').value,
                    description: document.getElementById('adm-pp-desc').value
                };
                try {
                    const r = await fetch('savePatchPanel.php', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
                    const d = await r.json();
                    if (d.success||d.id) {
                        showToast('Patch panel eklendi','success');
                        document.getElementById('adm-pp-modal').classList.remove('active');
                        loadAdminData();
                    } else showToast(d.error||'Kaydedilemedi','error');
                } catch(e) { showToast('Hata: '+e.message,'error'); }
            });

            document.getElementById('adm-fp-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const payload = {
                    rackId: document.getElementById('adm-fp-rack').value,
                    panelLetter: document.getElementById('adm-fp-letter').value,
                    totalFibers: document.getElementById('adm-fp-fibers').value,
                    positionInRack: document.getElementById('adm-fp-slot').value,
                    description: document.getElementById('adm-fp-desc').value
                };
                try {
                    const r = await fetch('saveFiberPanel.php', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
                    const d = await r.json();
                    if (d.success||d.id) {
                        showToast('Fiber panel eklendi','success');
                        document.getElementById('adm-fp-modal').classList.remove('active');
                        loadAdminData();
                    } else showToast(d.error||'Kaydedilemedi','error');
                } catch(e) { showToast('Hata: '+e.message,'error'); }
            });

            document.getElementById('adm-ep-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const payload = {
                    action: 'edit',
                    id: document.getElementById('adm-ep-id').value,
                    type: document.getElementById('adm-ep-type').value,
                    rackId: document.getElementById('adm-ep-rack').value,
                    positionInRack: document.getElementById('adm-ep-slot').value
                };
                try {
                    const r = await fetch('savePatchPanel.php', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
                    const d = await r.json();
                    if (d.success) {
                        showToast('Panel güncellendi','success');
                        document.getElementById('adm-ep-modal').classList.remove('active');
                        loadAdminData();
                    } else showToast(d.error||'Kaydedilemedi','error');
                } catch(e) { showToast('Hata: '+e.message,'error'); }
            });

            document.getElementById('adm-port-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const swId = document.getElementById('adm-port-sw-id').value;
                const portNum = document.getElementById('adm-port-num').value;
                const fd = new FormData();
                fd.append('switch_id', swId); fd.append('port', portNum);
                fd.append('type', document.getElementById('adm-port-type').value);
                fd.append('device', document.getElementById('adm-port-device').value);
                fd.append('ip', document.getElementById('adm-port-ip').value);
                fd.append('mac', document.getElementById('adm-port-mac').value);
                fd.append('connection_info_preserved', document.getElementById('adm-port-conn-info').value);
                try {
                    const r = await fetch('updatePort.php', {method:'POST', body:fd});
                    const d = await r.json();
                    if (d.success) {
                        showToast('Port güncellendi','success');
                        document.getElementById('adm-port-modal').classList.remove('active');
                        loadAdminPorts();
                    } else showToast(d.error||'Kaydedilemedi','error');
                } catch(e) { showToast('Hata: '+e.message,'error'); }
            });
        });

        // ─── DATA LOADING ────────────────────────────────────────────────
        let adminData = {};

        async function loadAdminData() {
            try {
                const resp = await fetch('getData.php');
                adminData = await resp.json();
                renderSwitchesList();
                renderRacksList();
                renderPanelsList();
                populateSwitchSelect();
            } catch(e) { console.error('loadAdminData:', e); }
        }

        // ─── SWITCHES ────────────────────────────────────────────────────
        function renderSwitchesList() {
            const el = document.getElementById('switches-list');
            const switches = adminData.switches || [];
            const racks = adminData.racks || [];
            if (!switches.length) { el.innerHTML = '<p style="color:var(--text-light)">Henüz switch yok.</p>'; return; }
            el.innerHTML = `<table><thead><tr>
                <th>Ad</th><th>Marka</th><th>Model</th><th>IP</th><th>Rack</th><th>Portlar</th><th>Durum</th><th>İşlem</th>
            </tr></thead><tbody>
            ${switches.map(sw => {
                const rack = racks.find(r => r.id == sw.rack_id);
                return `<tr>
                    <td>${sw.name}</td><td>${sw.brand||''}</td><td>${sw.model||''}</td>
                    <td>${sw.ip_address||''}</td><td>${rack ? rack.name : '-'}</td>
                    <td>${sw.ports}</td>
                    <td><span style="color:${sw.status==='online'?'var(--success)':'var(--danger)'}">
                        <i class="fas fa-circle" style="font-size:8px"></i> ${sw.status==='online'?'Online':'Offline'}
                    </span></td>
                    <td style="white-space:nowrap">
                        <button class="btn btn-primary" style="padding:6px 12px; font-size:13px;" onclick="editAdminSwitch(${JSON.stringify(sw).replace(/"/g,'&quot;')})">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-danger" style="padding:6px 12px; font-size:13px; margin-left:5px;" onclick="deleteAdminSwitch(${sw.id})">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            }).join('')}
            </tbody></table>`;
        }

        function openAdminSwitchModal(sw) {
            document.getElementById('adm-sw-id').value = sw ? sw.id : '';
            document.getElementById('adm-sw-name').value = sw ? sw.name : '';
            document.getElementById('adm-sw-brand').value = sw ? sw.brand : '';
            document.getElementById('adm-sw-model').value = sw ? sw.model : '';
            document.getElementById('adm-sw-ports').value = sw ? sw.ports : '48';
            document.getElementById('adm-sw-status').value = sw ? sw.status : 'online';
            document.getElementById('adm-sw-ip').value = sw ? (sw.ip_address||'') : '';
            // populate rack select
            const sel = document.getElementById('adm-sw-rack');
            sel.innerHTML = '<option value="">Seçiniz</option>' +
                (adminData.racks||[]).map(r => `<option value="${r.id}" ${sw&&sw.rack_id==r.id?'selected':''}>${r.name}</option>`).join('');
            document.getElementById('adm-sw-modal-title').textContent = sw ? 'Switch Düzenle' : 'Yeni Switch Ekle';
            document.getElementById('adm-sw-modal').classList.add('active');
        }

        function editAdminSwitch(sw) { openAdminSwitchModal(sw); }

        async function deleteAdminSwitch(id) {
            if (!confirm('Switch silinecek, emin misiniz?')) return;
            try {
                const r = await fetch('saveSwitch.php', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'delete', id:id})});
                const d = await r.json();
                if (d.success||d.id) { showToast('Switch silindi','success'); loadStats(); loadAdminData(); }
                else showToast(d.error||'Silinemedi','error');
            } catch(e) { showToast('Hata: '+e.message,'error'); }
        }

        // ─── RACKS ───────────────────────────────────────────────────────
        function renderRacksList() {
            const el = document.getElementById('racks-list');
            const racks = adminData.racks || [];
            const switches = adminData.switches || [];
            if (!racks.length) { el.innerHTML = '<p style="color:var(--text-light)">Henüz rack yok.</p>'; return; }
            el.innerHTML = `<table><thead><tr>
                <th>Ad</th><th>Konum</th><th>Slot</th><th>Switch Sayısı</th><th>İşlem</th>
            </tr></thead><tbody>
            ${racks.map(r => {
                const swCount = switches.filter(s => s.rack_id == r.id).length;
                return `<tr>
                    <td>${r.name}</td><td>${r.location||''}</td><td>${r.slots||42}</td><td>${swCount}</td>
                    <td style="white-space:nowrap">
                        <button class="btn btn-primary" style="padding:6px 12px; font-size:13px;" onclick="editAdminRack(${JSON.stringify(r).replace(/"/g,'&quot;')})">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-danger" style="padding:6px 12px; font-size:13px; margin-left:5px;" onclick="deleteAdminRack(${r.id})">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            }).join('')}
            </tbody></table>`;
        }

        function openAdminRackModal(rack) {
            document.getElementById('adm-rack-id').value = rack ? rack.id : '';
            document.getElementById('adm-rack-name').value = rack ? rack.name : '';
            document.getElementById('adm-rack-location').value = rack ? (rack.location||'') : '';
            document.getElementById('adm-rack-slots').value = rack ? (rack.slots||42) : 42;
            document.getElementById('adm-rack-desc').value = rack ? (rack.description||'') : '';
            document.getElementById('adm-rack-modal-title').textContent = rack ? 'Rack Düzenle' : 'Yeni Rack Ekle';
            document.getElementById('adm-rack-modal').classList.add('active');
        }

        function editAdminRack(rack) { openAdminRackModal(rack); }

        async function deleteAdminRack(id) {
            if (!confirm('Rack silinecek, emin misiniz?')) return;
            try {
                const r = await fetch('saveRack.php', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'delete', id:id})});
                const d = await r.json();
                if (d.success||d.id) { showToast('Rack silindi','success'); loadStats(); loadAdminData(); }
                else showToast(d.error||'Silinemedi','error');
            } catch(e) { showToast('Hata: '+e.message,'error'); }
        }

        // ─── PANELS ──────────────────────────────────────────────────────
        function renderPanelsList() {
            const el = document.getElementById('panels-list');
            const patches = adminData.patch_panels || [];
            const fibers = adminData.fiber_panels || [];
            const racks = adminData.racks || [];
            if (!patches.length && !fibers.length) { el.innerHTML = '<p style="color:var(--text-light)">Henüz panel yok.</p>'; return; }
            let rows = '';
            patches.forEach(p => {
                const rack = racks.find(r => r.id == p.rack_id);
                rows += `<tr><td>Patch ${p.panel_letter}</td><td>Patch Panel</td><td>${rack?rack.name:'-'}</td><td>${p.total_ports||24} Port</td><td>Slot ${p.position_in_rack||0}</td>
                    <td style="white-space:nowrap">
                        <button class="btn btn-primary" style="padding:6px 12px; font-size:13px;" onclick="editAdminPanel(${p.id},'patch')"><i class="fas fa-edit"></i></button>
                        <button class="btn btn-danger" style="padding:6px 12px; font-size:13px; margin-left:5px;" onclick="deleteAdminPanel(${p.id},'patch')"><i class="fas fa-trash"></i></button>
                    </td></tr>`;
            });
            fibers.forEach(f => {
                const rack = racks.find(r => r.id == f.rack_id);
                rows += `<tr><td>Fiber ${f.panel_letter}</td><td>Fiber Panel</td><td>${rack?rack.name:'-'}</td><td>${f.total_fibers||24} Fiber</td><td>Slot ${f.position_in_rack||0}</td>
                    <td style="white-space:nowrap">
                        <button class="btn btn-primary" style="padding:6px 12px; font-size:13px;" onclick="editAdminPanel(${f.id},'fiber')"><i class="fas fa-edit"></i></button>
                        <button class="btn btn-danger" style="padding:6px 12px; font-size:13px; margin-left:5px;" onclick="deleteAdminPanel(${f.id},'fiber')"><i class="fas fa-trash"></i></button>
                    </td></tr>`;
            });
            el.innerHTML = `<table><thead><tr><th>Panel</th><th>Tür</th><th>Rack</th><th>Kapasite</th><th>Slot</th><th>İşlem</th></tr></thead><tbody>${rows}</tbody></table>`;
        }

        function populatePanelSlots(rackSelectId, slotSelectId) {
            const rackId = document.getElementById(rackSelectId).value;
            const sel = document.getElementById(slotSelectId);
            sel.innerHTML = '<option value="">Seçiniz</option>';
            if (!rackId) return;
            const rack = (adminData.racks || []).find(r => r.id == rackId);
            if (!rack) return;
            const totalSlots = rack.slots || 42;
            const occupied = new Set();
            (adminData.switches || []).filter(s => s.rack_id == rackId && s.position_in_rack > 0)
                .forEach(s => occupied.add(parseInt(s.position_in_rack)));
            (adminData.patch_panels || []).filter(p => p.rack_id == rackId && p.position_in_rack > 0)
                .forEach(p => occupied.add(parseInt(p.position_in_rack)));
            (adminData.fiber_panels || []).filter(f => f.rack_id == rackId && f.position_in_rack > 0)
                .forEach(f => occupied.add(parseInt(f.position_in_rack)));
            for (let i = 1; i <= totalSlots; i++) {
                if (!occupied.has(i)) sel.innerHTML += `<option value="${i}">${i}</option>`;
            }
        }

        function openAdminPatchPanelModal() {
            const sel = document.getElementById('adm-pp-rack');
            sel.innerHTML = '<option value="">Seçiniz</option>' +
                (adminData.racks||[]).map(r=>`<option value="${r.id}">${r.name}</option>`).join('');
            document.getElementById('adm-pp-slot').innerHTML = '<option value="">Önce rack seçin</option>';
            document.getElementById('adm-pp-modal').classList.add('active');
        }

        function openAdminFiberPanelModal() {
            const sel = document.getElementById('adm-fp-rack');
            sel.innerHTML = '<option value="">Seçiniz</option>' +
                (adminData.racks||[]).map(r=>`<option value="${r.id}">${r.name}</option>`).join('');
            document.getElementById('adm-fp-slot').innerHTML = '<option value="">Önce rack seçin</option>';
            document.getElementById('adm-fp-modal').classList.add('active');
        }

        async function deleteAdminPanel(id, type) {
            if (!confirm('Panel silinecek, emin misiniz?')) return;
            try {
                const r = await fetch('savePatchPanel.php', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'delete', id:id, type:type})});
                const d = await r.json();
                if (d.success) { showToast('Panel silindi','success'); loadAdminData(); }
                else showToast(d.error||'Silinemedi','error');
            } catch(e) { showToast('Hata: '+e.message,'error'); }
        }

        function editAdminPanel(id, type) {
            const panel = type === 'fiber'
                ? (adminData.fiber_panels || []).find(f => f.id == id)
                : (adminData.patch_panels || []).find(p => p.id == id);
            if (!panel) return;
            document.getElementById('adm-ep-id').value = panel.id;
            document.getElementById('adm-ep-type').value = type;
            document.getElementById('adm-ep-info').textContent = (type === 'patch' ? 'Patch ' : 'Fiber ') + panel.panel_letter;
            // populate rack select
            const rackSel = document.getElementById('adm-ep-rack');
            rackSel.innerHTML = '<option value="">Seçiniz</option>' +
                (adminData.racks||[]).map(r => `<option value="${r.id}" ${r.id == panel.rack_id ? 'selected' : ''}>${r.name}</option>`).join('');
            // populate slot select with current rack, including current slot
            populatePanelSlotsEdit(panel.rack_id, panel.id, type, panel.position_in_rack);
            document.getElementById('adm-ep-modal').classList.add('active');
        }

        function populatePanelSlotsEdit(rackId, panelId, panelType, currentSlot) {
            const sel = document.getElementById('adm-ep-slot');
            sel.innerHTML = '<option value="">Seçiniz</option>';
            if (!rackId) return;
            const rack = (adminData.racks || []).find(r => r.id == rackId);
            if (!rack) return;
            const totalSlots = rack.slots || 42;
            const occupied = new Set();
            (adminData.switches || []).filter(s => s.rack_id == rackId && s.position_in_rack > 0)
                .forEach(s => occupied.add(parseInt(s.position_in_rack)));
            (adminData.patch_panels || []).filter(p => p.rack_id == rackId && p.position_in_rack > 0 && !(panelType === 'patch' && p.id == panelId))
                .forEach(p => occupied.add(parseInt(p.position_in_rack)));
            (adminData.fiber_panels || []).filter(f => f.rack_id == rackId && f.position_in_rack > 0 && !(panelType === 'fiber' && f.id == panelId))
                .forEach(f => occupied.add(parseInt(f.position_in_rack)));
            for (let i = 1; i <= totalSlots; i++) {
                if (!occupied.has(i)) sel.innerHTML += `<option value="${i}" ${i == currentSlot ? 'selected' : ''}>${i}</option>`;
            }
        }

        // ─── PORT YÖNETİMİ ───────────────────────────────────────────────
        const VLAN_TYPE_MAP = {50:'DEVICE',70:'AP',80:'KAMERA',120:'OTOMASYON',130:'IPTV',140:'SANTRAL',254:'SERVER',30:'FIBER'};

        function populateSwitchSelect() {
            const sel = document.getElementById('admin-switch-select');
            (adminData.switches||[]).forEach(sw => {
                const opt = document.createElement('option');
                opt.value = sw.id; opt.textContent = sw.name + (sw.ip_address ? ' ('+sw.ip_address+')' : '');
                sel.appendChild(opt);
            });
        }

        async function loadAdminPorts() {
            const swId = document.getElementById('admin-switch-select').value;
            document.getElementById('admin-vlan-btn').disabled = !swId;
            document.getElementById('admin-reset-btn').disabled = !swId;
            const infoBar = document.getElementById('admin-switch-info');
            if (!swId) {
                document.getElementById('admin-ports-grid').innerHTML = '<p style="color:var(--text-light)">Yukarıdan switch seçin.</p>';
                infoBar.style.display = 'none';
                return;
            }
            // Show switch info bar
            const sw = (adminData.switches||[]).find(s => s.id == swId);
            if (sw) {
                const rack = (adminData.racks||[]).find(r => r.id == sw.rack_id);
                document.getElementById('info-sw-name').textContent = sw.name || '-';
                document.getElementById('info-sw-ip').textContent = sw.ip_address || '-';
                document.getElementById('info-sw-model').textContent = [sw.brand, sw.model].filter(Boolean).join(' ') || '-';
                document.getElementById('info-sw-ports').textContent = sw.ports || '-';
                document.getElementById('info-sw-rack').textContent = rack ? rack.name : '-';
                infoBar.style.display = 'block';
            }
            try {
                const resp = await fetch('getData.php');
                const data = await resp.json();
                const ports = (data.ports||{})[swId] || [];
                renderAdminPorts(swId, ports);
            } catch(e) { showToast('Port verisi alınamadı','error'); }
        }

        // Type → badge colour map (matches index.php)
        const TYPE_COLORS = {
            'DEVICE':'#3b82f6','SERVER':'#8b5cf6','AP':'#06b6d4','KAMERA':'#ef4444',
            'OTOMASYON':'#10b981','IPTV':'#f59e0b','SANTRAL':'#f97316','FIBER':'#6366f1',
            'ETHERNET':'#64748b','HUB':'#84cc16','BOŞ':'#334155'
        };

        function renderAdminPorts(swId, ports) {
            const grid = document.getElementById('admin-ports-grid');
            if (!ports.length) { grid.innerHTML = '<p style="color:var(--text-light)">Port bulunamadı.</p>'; return; }
            const sw = (adminData.switches||[]).find(s => s.id == swId);
            const total = sw ? sw.ports : Math.max(...ports.map(p=>p.port), 24);
            grid.innerHTML = '';
            for (let i = 1; i <= total; i++) {
                const conn = ports.find(p => p.port == i) || {port:i, type:'BOŞ', device:'', ip:'', mac:'', snmp_vlan_id:null};
                const vlan = conn.snmp_vlan_id;
                const vlanType = vlan && VLAN_TYPE_MAP[vlan];
                const displayType = vlanType || conn.type || 'BOŞ';
                const isDown = conn.is_down || false;
                const isEmpty = !conn.device && displayType === 'BOŞ';
                const color = isDown ? 'var(--danger)' : (TYPE_COLORS[displayType] || 'var(--text-light)');
                const borderColor = isDown ? 'rgba(239,68,68,0.5)' : (isEmpty ? 'var(--border)' : color + '66');
                const portDiv = document.createElement('div');
                portDiv.style.cssText = `background:rgba(15,23,42,0.8); border:1px solid ${borderColor}; border-radius:8px; padding:10px; cursor:pointer; transition:all 0.2s;`;
                portDiv.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                        <span style="font-size:16px; font-weight:700; color:var(--text);">${i}</span>
                        <span style="font-size:10px; font-weight:600; padding:2px 6px; border-radius:8px; background:${color}22; color:${color}; border:1px solid ${color}44;">
                            ${displayType}${isDown?' ↓':''}
                        </span>
                    </div>
                    <div style="font-size:11px; color:var(--text-light); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; min-height:16px;">${conn.device||''}</div>
                    ${vlan && vlan > 1 ? `<div style="font-size:10px; color:#38bdf8; margin-top:2px;">VLAN ${vlan}</div>` : '<div style="font-size:10px; min-height:14px;"></div>'}
                    <button class="btn btn-primary" style="width:100%; margin-top:6px; padding:4px; font-size:11px;" onclick="event.stopPropagation();openAdminPortModal(${swId}, ${i})">
                        <i class="fas fa-edit"></i> Düzenle
                    </button>
                `;
                portDiv.onmouseenter = () => portDiv.style.borderColor = color;
                portDiv.onmouseleave = () => portDiv.style.borderColor = borderColor;
                grid.appendChild(portDiv);
            }
        }

        async function openAdminPortModal(swId, portNum) {
            try {
                const resp = await fetch('getData.php');
                const data = await resp.json();
                const ports = (data.ports||{})[swId] || [];
                const conn = ports.find(p => p.port == portNum) || {port:portNum, type:'BOŞ', device:'', ip:'', mac:''};
                document.getElementById('adm-port-sw-id').value = swId;
                document.getElementById('adm-port-num').value = portNum;
                document.getElementById('adm-port-modal-title').textContent = `Port ${portNum} Düzenle`;
                document.getElementById('adm-port-type').value = conn.type || 'BOŞ';
                document.getElementById('adm-port-device').value = conn.device || '';
                document.getElementById('adm-port-ip').value = conn.ip || '';
                document.getElementById('adm-port-mac').value = conn.mac || '';
                document.getElementById('adm-port-conn-info').value = conn.connection_info_preserved || '';
                const vlanBadge = document.getElementById('adm-port-vlan-badge');
                if (conn.snmp_vlan_id > 1) {
                    vlanBadge.textContent = 'SNMP VLAN ' + conn.snmp_vlan_id;
                    vlanBadge.style.display = 'inline-block';
                } else {
                    vlanBadge.style.display = 'none';
                }
                document.getElementById('adm-port-modal').classList.add('active');
            } catch(e) { showToast('Port verisi alınamadı','error'); }
        }

        async function clearAdminPort() {
            const swId = document.getElementById('adm-port-sw-id').value;
            const portNum = document.getElementById('adm-port-num').value;
            if (!confirm(`Port ${portNum} boşa çekilecek, emin misiniz?`)) return;
            const fd = new FormData();
            fd.append('switch_id', swId); fd.append('port', portNum); fd.append('action', 'clear');
            try {
                const r = await fetch('updatePort.php', {method:'POST', body:fd});
                const d = await r.json();
                if (d.success) {
                    showToast('Port boşa çekildi','success');
                    document.getElementById('adm-port-modal').classList.remove('active');
                    loadAdminPorts();
                } else showToast(d.error||'İşlem başarısız','error');
            } catch(e) { showToast('Hata: '+e.message,'error'); }
        }

        async function adminVlanSync() {
            const swId = document.getElementById('admin-switch-select').value;
            if (!swId) return;
            showToast('VLAN verisi okunuyor...','info');
            try {
                const r = await fetch(`snmp_data_api.php?action=php_vlan_sync&switch_id=${swId}`, {method:'POST'});
                const d = await r.json();
                if (d.success) { showToast(`${d.updated_ports||0} port güncellendi`,'success'); loadAdminPorts(); }
                else showToast(d.error||'VLAN güncellenemedi','error');
            } catch(e) { showToast('Hata: '+e.message,'error'); }
        }

        async function adminResetAllPorts() {
            const swId = document.getElementById('admin-switch-select').value;
            if (!swId) return;
            const sw = (adminData.switches||[]).find(s => s.id == swId);
            if (!confirm(`${sw?sw.name:'Switch'} üzerindeki tüm portlar boşa çekilecek, emin misiniz?`)) return;
            try {
                const fd = new FormData(); fd.append('switch_id', swId); fd.append('action','reset_all');
                const r = await fetch('updatePort.php', {method:'POST', body:fd});
                const d = await r.json();
                if (d.success) { showToast('Tüm portlar boşa çekildi','success'); loadAdminPorts(); }
                else showToast(d.error||'İşlem başarısız','error');
            } catch(e) { showToast('Hata: '+e.message,'error'); }
        }

        async function cleanupPhantomPorts() {
            if (!confirm('Tüm switch\'ler için fantom portlar silinecek (port sayısını aşan port satırları). Devam edilsin mi?')) return;
            try {
                const r = await fetch('snmp_data_api.php?action=cleanup_phantom_ports', {method:'POST'});
                const d = await r.json();
                if (d.success) {
                    if (d.deleted > 0) {
                        showToast(`${d.deleted} fantom port silindi`, 'success');
                        console.info('Fantom port temizleme detayları:', (d.details||[]).join('; '));
                    } else {
                        showToast('Fantom port bulunamadı, her şey temiz', 'success');
                    }
                    const swId = document.getElementById('admin-switch-select').value;
                    if (swId) loadAdminPorts();
                } else showToast(d.error||'İşlem başarısız','error');
            } catch(e) { showToast('Hata: '+e.message,'error'); }
        }
    </script>

    <!-- ─── MODALS ──────────────────────────────────────────────────────── -->

    <!-- Switch Modal -->
    <div class="modal-overlay" id="adm-sw-modal" onclick="if(event.target===this)this.classList.remove('active')">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title" id="adm-sw-modal-title">Yeni Switch Ekle</h3>
                <button class="modal-close" onclick="document.getElementById('adm-sw-modal').classList.remove('active')">&times;</button>
            </div>
            <form id="adm-sw-form">
                <input type="hidden" id="adm-sw-id">
                <div class="form-group"><label class="form-group">Switch Adı *</label>
                    <input type="text" id="adm-sw-name" class="form-group" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text); font-size:16px;" placeholder="Ör: SW35-BALO" required></div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px;">
                    <div class="form-group"><label>Marka</label>
                        <select id="adm-sw-brand" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);">
                            <option value="">Seçiniz</option>
                            <option value="Cisco">Cisco</option><option value="HP">HP</option>
                            <option value="Juniper">Juniper</option><option value="Aruba">Aruba</option>
                            <option value="MikroTik">MikroTik</option>
                        </select></div>
                    <div class="form-group"><label>Model</label>
                        <input type="text" id="adm-sw-model" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Ör: CBS350-24FP"></div>
                </div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px;">
                    <div class="form-group"><label>Port Sayısı *</label>
                        <select id="adm-sw-ports" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" required>
                            <option value="24">24 Port</option><option value="28">28 Port</option>
                            <option value="48" selected>48 Port</option><option value="52">52 Port</option>
                        </select></div>
                    <div class="form-group"><label>Durum *</label>
                        <select id="adm-sw-status" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" required>
                            <option value="online">Çevrimiçi</option><option value="offline">Çevrimdışı</option>
                        </select></div>
                </div>
                <div class="form-group"><label>Rack Kabin *</label>
                    <select id="adm-sw-rack" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" required></select></div>
                <div class="form-group"><label>IP Adresi</label>
                    <input type="text" id="adm-sw-ip" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Ör: 172.18.1.214"></div>
                <div style="display:flex; gap:10px; margin-top:20px;">
                    <button type="button" class="btn" style="flex:1; background:var(--border); color:var(--text);" onclick="document.getElementById('adm-sw-modal').classList.remove('active')">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex:1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Rack Modal -->
    <div class="modal-overlay" id="adm-rack-modal" onclick="if(event.target===this)this.classList.remove('active')">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title" id="adm-rack-modal-title">Yeni Rack Ekle</h3>
                <button class="modal-close" onclick="document.getElementById('adm-rack-modal').classList.remove('active')">&times;</button>
            </div>
            <form id="adm-rack-form">
                <input type="hidden" id="adm-rack-id">
                <div class="form-group"><label>Rack Adı *</label>
                    <input type="text" id="adm-rack-name" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Ör: Ana Rack #1" required></div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px;">
                    <div class="form-group"><label>Konum</label>
                        <input type="text" id="adm-rack-location" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Ör: Sunucu Odası"></div>
                    <div class="form-group"><label>Slot Sayısı</label>
                        <input type="number" id="adm-rack-slots" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" min="1" max="100" value="42"></div>
                </div>
                <div class="form-group"><label>Açıklama</label>
                    <textarea id="adm-rack-desc" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" rows="3" placeholder="Rack hakkında açıklama"></textarea></div>
                <div style="display:flex; gap:10px; margin-top:20px;">
                    <button type="button" class="btn" style="flex:1; background:var(--border); color:var(--text);" onclick="document.getElementById('adm-rack-modal').classList.remove('active')">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex:1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Patch Panel Modal -->
    <div class="modal-overlay" id="adm-pp-modal" onclick="if(event.target===this)this.classList.remove('active')">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Patch Panel Ekle</h3>
                <button class="modal-close" onclick="document.getElementById('adm-pp-modal').classList.remove('active')">&times;</button>
            </div>
            <form id="adm-pp-form">
                <div class="form-group"><label>Rack *</label>
                    <select id="adm-pp-rack" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" required onchange="populatePanelSlots('adm-pp-rack','adm-pp-slot')"></select></div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px;">
                    <div class="form-group"><label>Panel Harfi *</label>
                        <input type="text" id="adm-pp-letter" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Ör: A" maxlength="5" required></div>
                    <div class="form-group"><label>Port Sayısı</label>
                        <input type="number" id="adm-pp-ports" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" value="24" min="1" max="96"></div>
                </div>
                <div class="form-group"><label>Slot Numarası *</label>
                    <select id="adm-pp-slot" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" required>
                        <option value="">Önce rack seçin</option>
                    </select></div>
                <div class="form-group"><label>Açıklama</label>
                    <input type="text" id="adm-pp-desc" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Opsiyonel"></div>
                <div style="display:flex; gap:10px; margin-top:20px;">
                    <button type="button" class="btn" style="flex:1; background:var(--border); color:var(--text);" onclick="document.getElementById('adm-pp-modal').classList.remove('active')">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex:1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Fiber Panel Modal -->
    <div class="modal-overlay" id="adm-fp-modal" onclick="if(event.target===this)this.classList.remove('active')">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Fiber Panel Ekle</h3>
                <button class="modal-close" onclick="document.getElementById('adm-fp-modal').classList.remove('active')">&times;</button>
            </div>
            <form id="adm-fp-form">
                <div class="form-group"><label>Rack *</label>
                    <select id="adm-fp-rack" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" required onchange="populatePanelSlots('adm-fp-rack','adm-fp-slot')"></select></div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px;">
                    <div class="form-group"><label>Panel Harfi *</label>
                        <input type="text" id="adm-fp-letter" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Ör: A" maxlength="5" required></div>
                    <div class="form-group"><label>Fiber Sayısı</label>
                        <input type="number" id="adm-fp-fibers" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" value="24" min="1" max="144"></div>
                </div>
                <div class="form-group"><label>Slot Numarası *</label>
                    <select id="adm-fp-slot" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" required>
                        <option value="">Önce rack seçin</option>
                    </select></div>
                <div class="form-group"><label>Açıklama</label>
                    <input type="text" id="adm-fp-desc" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Opsiyonel"></div>
                <div style="display:flex; gap:10px; margin-top:20px;">
                    <button type="button" class="btn" style="flex:1; background:var(--border); color:var(--text);" onclick="document.getElementById('adm-fp-modal').classList.remove('active')">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex:1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Panel Edit Modal -->
    <div class="modal-overlay" id="adm-ep-modal" onclick="if(event.target===this)this.classList.remove('active')">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Panel Düzenle: <span id="adm-ep-info"></span></h3>
                <button class="modal-close" onclick="document.getElementById('adm-ep-modal').classList.remove('active')">&times;</button>
            </div>
            <form id="adm-ep-form">
                <input type="hidden" id="adm-ep-id">
                <input type="hidden" id="adm-ep-type">
                <div class="form-group"><label>Rack *</label>
                    <select id="adm-ep-rack" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" required
                        onchange="populatePanelSlotsEdit(this.value, document.getElementById('adm-ep-id').value, document.getElementById('adm-ep-type').value, 0)"></select></div>
                <div class="form-group"><label>Slot Numarası *</label>
                    <select id="adm-ep-slot" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" required>
                        <option value="">Seçiniz</option>
                    </select></div>
                <div style="display:flex; gap:10px; margin-top:20px;">
                    <button type="button" class="btn" style="flex:1; background:var(--border); color:var(--text);" onclick="document.getElementById('adm-ep-modal').classList.remove('active')">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex:1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Port Edit Modal -->
    <div class="modal-overlay" id="adm-port-modal" onclick="if(event.target===this)this.classList.remove('active')">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title" id="adm-port-modal-title">Port Düzenle</h3>
                <button class="modal-close" onclick="document.getElementById('adm-port-modal').classList.remove('active')">&times;</button>
            </div>
            <form id="adm-port-form">
                <input type="hidden" id="adm-port-sw-id">
                <input type="hidden" id="adm-port-num">
                <div class="form-group">
                    <label>Bağlantı Türü
                        <span id="adm-port-vlan-badge" style="display:none; margin-left:8px; background:var(--primary); color:white; font-size:11px; padding:2px 8px; border-radius:10px;"></span>
                    </label>
                    <select id="adm-port-type" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);">
                        <option value="BOŞ">BOŞ</option><option value="DEVICE">DEVICE</option>
                        <option value="SERVER">SERVER</option><option value="AP">AP</option>
                        <option value="KAMERA">KAMERA</option><option value="IPTV">IPTV</option>
                        <option value="OTOMASYON">OTOMASYON</option><option value="SANTRAL">SANTRAL</option>
                        <option value="FIBER">FIBER</option><option value="ETHERNET">ETHERNET</option>
                        <option value="HUB">HUB</option>
                    </select>
                </div>
                <div class="form-group"><label>Cihaz Adı/Açıklama</label>
                    <input type="text" id="adm-port-device" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Ör: OTOMASYON"></div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px;">
                    <div class="form-group"><label>IP Adresi</label>
                        <input type="text" id="adm-port-ip" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Ör: 172.18.120.37"></div>
                    <div class="form-group"><label>MAC Adresi</label>
                        <input type="text" id="adm-port-mac" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text);" placeholder="Ör: 00:18:bb:02:8a:47"></div>
                </div>
                <div class="form-group">
                    <label><i class="fas fa-link" style="color:var(--primary);"></i> Connection Bilgisi
                        <small style="color:var(--text-light); font-weight:normal;">(Excel'den gelen ek bağlantı bilgileri)</small>
                    </label>
                    <textarea id="adm-port-conn-info" style="width:100%; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text); resize:vertical;" rows="3" placeholder="Ek bağlantı bilgileri, oda/cihaz notları vb."></textarea>
                    <small style="color:var(--text-light);"><i class="fas fa-info-circle"></i> Bu alan panel bilgisi girilse bile korunur</small>
                </div>
                <div style="display:flex; gap:10px; margin-top:20px;">
                    <button type="button" class="btn btn-danger" style="flex:1;" onclick="clearAdminPort()">
                        <i class="fas fa-trash"></i> Boşa Çek
                    </button>
                    <button type="button" class="btn" style="flex:1; background:var(--border); color:var(--text);" onclick="document.getElementById('adm-port-modal').classList.remove('active')">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex:1;"><i class="fas fa-save"></i> Kaydet</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Floating monitor return button -->
    <a href="index.php" class="monitor-btn" title="İzleme Ekranına Dön">
        <i class="fas fa-desktop"></i>
    </a>

    <!-- Excel İçe Aktarma Modal -->
    <div id="excel-import-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;align-items:center;justify-content:center;">
        <div style="background:rgba(15,23,42,0.97);border:1px solid rgba(56,189,248,0.3);border-radius:16px;width:90vw;height:90vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 25px 50px rgba(0,0,0,0.5);">
            <div style="display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid rgba(56,189,248,0.2);">
                <span style="color:#e2e8f0;font-weight:600;font-size:1rem;"><i class="fas fa-file-import" style="color:#38bdf8;margin-right:8px;"></i>Excel İçe Aktarma</span>
                <button onclick="document.getElementById('excel-import-modal').style.display='none';" style="background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);color:#ef4444;border-radius:8px;padding:6px 12px;cursor:pointer;font-size:1.1rem;">&times;</button>
            </div>
            <iframe src="device_import.php" style="flex:1;border:none;width:100%;background:transparent;"></iframe>
        </div>
    </div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const modal = document.getElementById('excel-import-modal');
        if (modal) {
            modal.addEventListener('click', function(e) {
                if (e.target === modal) modal.style.display = 'none';
            });
        }
    });
    function openExcelImportModal() {
        const m = document.getElementById('excel-import-modal');
        if (m) m.style.display = 'flex';
    }
    </script>
</body>
</html>
