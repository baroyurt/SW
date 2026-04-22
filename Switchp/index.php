<?php
// Require authentication
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

$currentUser = $auth->getUser();

// Prevent caching to avoid stale JavaScript issues
header("Cache-Control: no-cache, no-store, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate, max-age=0">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Modern Rack & Switch Yönetim Sistemi</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css?v=<?php echo time(); ?>">
    <style>
        /* CSS KODLARI - AYNI KALDI */
        html { zoom: 0.9; }

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
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Loading Screen */
        .loading-screen {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: var(--dark);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            transition: opacity 0.5s ease;
        }
        
        .loading-screen.hidden {
            opacity: 0;
            pointer-events: none;
        }
        
        .loader {
            width: 80px;
            height: 80px;
            position: relative;
        }
        
        .loader-dot {
            position: absolute;
            width: 16px;
            height: 16px;
            background: var(--primary);
            border-radius: 50%;
            animation: loader 1.4s infinite;
        }
        
        .loader-dot:nth-child(1) { animation-delay: 0s; }
        .loader-dot:nth-child(2) { animation-delay: 0.2s; }
        .loader-dot:nth-child(3) { animation-delay: 0.4s; }
        
        @keyframes loader {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-30px); }
        }
        
        /* Sidebar */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 280px;
            height: 100vh;
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(10px);
            border-right: 1px solid rgba(56, 189, 248, 0.2);
            padding: 20px;
            overflow-y: auto;
            z-index: 100;
            transition: transform 0.3s ease;
        }
        
        @media (max-width: 1024px) {
            .sidebar {
                transform: translateX(-100%);
            }
            .sidebar.active {
                transform: translateX(0);
            }
        }
        
        .sidebar-toggle {
            position: fixed;
            left: 20px;
            top: 20px;
            z-index: 101;
            background: var(--primary);
            border: none;
            color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            cursor: pointer;
            display: none;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
        }
        
        @media (max-width: 1024px) {
            .sidebar-toggle {
                display: flex;
                align-items: center;
                justify-content: center;
            }
        }
        
        /* Ana Sayfa Butonu - SAĞ ALT KÖŞE */
        .home-button {
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
        }

        .home-button:hover {
            transform: scale(1.15);
            box-shadow: 0 8px 30px rgba(16, 185, 129, 0.6);
        }

        @media (max-width: 1024px) {
            .home-button {
                right: 20px;
                bottom: 20px;
            }
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        
        .logo i {
            font-size: 2rem;
            color: var(--primary);
        }
        
        .logo h1 {
            font-size: 1.3rem;
            color: var(--text);
        }
        
        /* Navigation */
        .nav-section {
            margin-bottom: 30px;
        }
        
        .nav-title {
            font-size: 0.9rem;
            color: var(--text-light);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 15px;
            background: transparent;
            border: none;
            color: var(--text-light);
            width: 100%;
            text-align: left;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 5px;
        }
        
        .nav-item:hover {
            background: rgba(56, 189, 248, 0.1);
            color: var(--text);
            transform: translateX(5px);
        }
        
        .nav-item.active {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            box-shadow: 0 5px 20px rgba(59, 130, 246, 0.4);
        }
        
        /* Main Content */
        .main-content {
            margin-left: 280px;
            padding: 20px;
            min-height: 100vh;
        }
        
        @media (max-width: 1024px) {
            .main-content {
                margin-left: 0;
            }
        }
        
        /* Page Content */
        .page-content {
            display: none;
            opacity: 0;
            transform: translateY(20px);
            transition: opacity 0.3s ease, transform 0.3s ease;
        }
        
        .page-content.active {
            display: block;
            opacity: 1;
            transform: translateY(0);
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        /* Top Bar */
        .top-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding: 15px 25px;
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            border: 1px solid rgba(56, 189, 248, 0.3);
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .page-title {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.5rem;
            color: var(--text);
        }
        
        .search-box {
            position: relative;
            flex: 1;
            max-width: 400px;
        }
        
        .search-input {
            width: 100%;
            padding: 12px 20px 12px 45px;
            background: rgba(15, 23, 42, 0.8);
            border: 2px solid rgba(56, 189, 248, 0.3);
            border-radius: 10px;
            color: var(--text);
            font-size: 0.95rem;
            transition: all 0.3s ease;
        }
        
        .search-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 20px rgba(56, 189, 248, 0.3);
        }
        
        .search-icon {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--primary);
        }
        
        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.8) 100%);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(56, 189, 248, 0.3);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(56, 189, 248, 0.3);
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, transparent 0%, rgba(56, 189, 248, 0.1) 100%);
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .stat-card:hover::before {
            opacity: 1;
        }
        
        .stat-icon {
            font-size: 2.5rem;
            color: var(--primary);
            margin-bottom: 15px;
        }
        
        .stat-value {
            font-size: 2.2rem;
            font-weight: bold;
            color: var(--text);
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9rem;
            color: var(--text-light);
        }
        
        /* Dashboard'da renkli slotlar */
        .dashboard-rack .rack-slot.filled {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        }

        .dashboard-rack .rack-slot.empty {
            background: rgba(15, 23, 42, 0.9);
        }

        /* Dashboard kartlarına özel class ekle */
        .dashboard-rack .rack-card {
            /* Dashboard'a özel stiller */
        }

        /* ── Modern Rack Summary Visual ──────────────────────────── */
        .rack-summary { margin-bottom: 16px; }

        .rack-slot-strip {
            display: flex;
            gap: 2px;
            flex-wrap: wrap;
            padding: 8px 10px;
            background: rgba(15, 23, 42, 0.6);
            border-radius: 8px;
            border: 1px solid rgba(56, 189, 248, 0.08);
            margin-bottom: 10px;
            min-height: 36px;
            align-content: flex-start;
        }
        .slot-dot {
            width: 9px;
            height: 9px;
            border-radius: 2px;
            flex-shrink: 0;
        }
        .slot-dot.sw-dot  { background: #3b82f6; }
        .slot-dot.pp-dot  { background: #8b5cf6; }
        .slot-dot.fp-dot  { background: #06b6d4; }
        .slot-dot.em-dot  { background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.08); }

        .rack-stat-badges {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }
        .rstat {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 3px 11px;
            border-radius: 20px;
            font-size: 0.78rem;
            font-weight: 600;
            white-space: nowrap;
        }
        .rstat.sw { background: rgba(59,130,246,0.15); border: 1px solid rgba(59,130,246,0.4); color: #93c5fd; }
        .rstat.pp { background: rgba(139,92,246,0.15);  border: 1px solid rgba(139,92,246,0.4);  color: #c4b5fd; }
        .rstat.fp { background: rgba(6,182,212,0.15);   border: 1px solid rgba(6,182,212,0.4);   color: #67e8f9; }
        .rstat.em { background: rgba(100,116,139,0.10); border: 1px solid rgba(100,116,139,0.3); color: #94a3b8; }

        .rack-usage-bar {
            height: 5px;
            background: rgba(100,116,139,0.2);
            border-radius: 3px;
            overflow: hidden;
        }
        .rack-usage-fill {
            height: 100%;
            border-radius: 3px;
            transition: width 0.5s ease;
        }

        /* ── Modern Switch Card Visual ───────────────────────────── */
        .sw-card-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        .sw-brand-badge {
            background: linear-gradient(135deg, rgba(59,130,246,0.2), rgba(37,99,235,0.3));
            border: 1px solid rgba(59,130,246,0.5);
            color: #60a5fa;
            font-weight: 700;
            font-size: 0.68rem;
            padding: 3px 8px;
            border-radius: 8px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        .sw-status-indicator {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.78rem;
            font-weight: 600;
        }
        .sw-status-indicator.online  { color: #10b981; }
        .sw-status-indicator.offline { color: #ef4444; }
        .sw-status-dot2 {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .sw-status-dot2.online  { background: #10b981; box-shadow: 0 0 6px #10b981; }
        .sw-status-dot2.offline { background: #ef4444; box-shadow: 0 0 6px #ef4444; }

        .sw-port-strip {
            display: flex;
            flex-wrap: wrap;
            gap: 3px;
            padding: 9px 8px;
            background: rgba(15, 23, 42, 0.5);
            border-radius: 8px;
            border: 1px solid rgba(56,189,248,0.08);
            margin-bottom: 10px;
            min-height: 30px;
            align-content: flex-start;
            overflow-x: hidden;
        }
        .sw-port-dot {
            width: 9px;
            height: 9px;
            border-radius: 2px;
            flex-shrink: 0;
            transition: transform 0.12s ease;
        }
        .sw-port-dot:hover { transform: scale(1.5); }
        .sw-port-dot.used { background: #10b981; box-shadow: 0 0 4px rgba(16,185,129,0.4); }
        .sw-port-dot.free { background: rgba(100,116,139,0.25); border: 1px solid rgba(100,116,139,0.3); }

        .sw-usage-bar {
            height: 4px;
            background: rgba(100,116,139,0.2);
            border-radius: 2px;
            overflow: hidden;
            margin-bottom: 14px;
        }
        .sw-usage-fill {
            height: 100%;
            background: linear-gradient(90deg, #3b82f6, #10b981);
            border-radius: 2px;
            transition: width 0.5s ease;
        }

        /* Rack detail modal için renk legend'ı */
        .color-legend {
            display: flex;
            gap: 10px;
            margin: 15px 0;
            flex-wrap: wrap;
        }

        .color-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .color-box {
            width: 20px;
            height: 20px;
            border-radius: 4px;
            border: 1px solid var(--border);
        }

        .color-box.switch {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
        }

        .color-box.patch-panel {
            background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
        }

        .color-box.fiber-panel {
            background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
        }

        .color-box.empty {
            background: rgba(15, 23, 42, 0.9);
        }

        .color-label {
            font-size: 0.85rem;
            color: var(--text-light);
        }
        
        /* Rack Grid */
        .racks-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }
        
        .rack-card {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.8) 100%);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 25px;
            border: 2px solid transparent;
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }
        
        .rack-card:hover {
            border-color: var(--primary);
            transform: translateY(-8px);
            box-shadow: 0 15px 40px rgba(56, 189, 248, 0.3);
        }
        
        .rack-card.selected {
            border-color: var(--success);
            background: rgba(16, 185, 129, 0.1);
        }
        
        .rack-3d {
            height: 150px;
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border-radius: 12px;
            margin-bottom: 20px;
            position: relative;
            overflow: hidden;
            border: 2px solid var(--border);
        }
        
        .rack-3d::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 20px,
                rgba(56, 189, 248, 0.1) 20px,
                rgba(56, 189, 248, 0.1) 22px
            );
        }
        
        .rack-slots {
            position: absolute;
            top: 10px;
            left: 10px;
            right: 10px;
            bottom: 10px;
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        
        .rack-slot {
            flex: 1;
            background: rgba(15, 23, 42, 0.9);
            border-radius: 4px;
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
        }
        
        /* RACK SLOT RENKLERİ */
        .rack-slot.switch {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            border-color: #3b82f6;
        }
        
        .rack-slot.patch-panel {
            background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
            border-color: #8b5cf6;
        }
        
        .rack-slot.fiber-panel {
            background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
            border-color: #06b6d4;
        }
        
        .rack-slot.empty {
            background: rgba(15, 23, 42, 0.9);
            border-color: var(--border);
        }

        .rack-slot.switch.filled {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            border-color: #3b82f6;
        }

        .rack-slot.patch-panel.filled {
            background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
            border-color: #8b5cf6;
        }

        .rack-slot.fiber-panel.filled {
            background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
            border-color: #06b6d4;
        }
        
        /* Boş slotlar için: */
        .rack-slot.empty {
            background: rgba(15, 23, 42, 0.9);
            border-color: var(--border);
        }

        /* Dolu slotlar için - bu sorunu yaratıyor olabilir */
        .rack-slot.switch.filled {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            border-color: #3b82f6;
        }

        .rack-slot.patch-panel.filled {
            background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
            border-color: #8b5cf6;
        }

        .rack-slot.fiber-panel.filled {
            background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
            border-color: #06b6d4;
        }
        
        /* Rack slot etiketleri */
        .slot-label {
            position: absolute;
            top: 2px;
            left: 2px;
            font-size: 0.6rem;
            color: white;
            font-weight: bold;
            z-index: 2;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
        }
        
        .panel-label {
            position: absolute;
            bottom: 2px;
            right: 2px;
            font-size: 0.7rem;
            color: white;
            font-weight: bold;
            background: rgba(0,0,0,0.5);
            padding: 1px 4px;
            border-radius: 3px;
        }
        
        .rack-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .rack-title {
            font-size: 1.3rem;
            color: var(--text);
            font-weight: bold;
        }
        
        .rack-switches {
            background: var(--dark);
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.9rem;
            color: var(--text-light);
        }
        
        .rack-info {
            display: flex;
            justify-content: space-between;
            margin-bottom: 15px;
            font-size: 0.9rem;
            color: var(--text-light);
        }
        
        .rack-location {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .rack-switch-preview {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .preview-switch {
            background: var(--dark);
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 0.8rem;
            color: var(--text-light);
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }
        
        .preview-switch:hover {
            border-color: var(--primary);
            color: var(--text);
        }
        
        /* Switch Detail Panel */
        .detail-panel {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.9) 100%);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            border: 2px solid rgba(56, 189, 248, 0.3);
            margin-bottom: 30px;
        }

        /* When port detail is triggered from an embedded iframe (e.g. reports),
           float it over the current page instead of navigating away */
        .detail-panel.from-reports {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: 950;
            margin: 0;
            border-radius: 0;
            overflow-y: auto;
            padding: 30px;
            /* fully opaque so sidebar is hidden */
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        }
        .detail-panel.from-reports .btn-close-overlay {
            display: inline-flex !important;
        }
        /* Hidden by default; shown only in from-reports mode */
        .btn-close-overlay {
            display: none !important;
        }
        
        .detail-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid rgba(56, 189, 248, 0.2);
            flex-wrap: wrap;
            gap: 20px;
        }
        
        /* ── Switch Sağlık Bilgi Barı ─────────────────────────────── */
        #switch-health-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 22px;
            padding: 14px 18px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 12px;
        }
        .health-badge {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
            padding: 10px 16px;
            border-radius: 10px;
            font-weight: 500;
            white-space: nowrap;
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(56, 189, 248, 0.15);
            color: var(--text-light);
            min-width: 80px;
        }
        .health-badge .hb-icon { font-size: 1.2rem; margin-bottom: 2px; }
        .health-badge .hb-label { color: #64748b; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; }
        .health-badge .hb-val { color: #e2e8f0; font-size: 1rem; font-weight: 700; }
        .health-badge.ok    { border-color: rgba(16,185,129,0.35); }
        .health-badge.warn  { border-color: rgba(245,158,11,0.45); }
        .health-badge.crit  { border-color: rgba(239,68,68,0.45); }
        .health-badge.poe   { border-color: rgba(245,158,11,0.3); min-width: 130px; /* wider to fit "Xw kullanılan / Xw kalan" two-line format */ }
        .health-badge.info  { border-color: rgba(56,189,248,0.25); min-width: 120px; }
        #switch-health-loading {
            color: #64748b; font-size: 0.82rem;
            display: flex; align-items: center; gap: 6px;
        }
        .health-cache-note {
            font-size: 0.72rem;
            color: #64748b;
            align-self: center;
            margin-left: 4px;
        }

        .switch-visual {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 30px;
        }
        
        .switch-3d {
            width: 250px;
            height: 250px;
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border-radius: 15px;
            border: 3px solid var(--border);
            position: relative;
            overflow: hidden;
        }
        
        .switch-front {
            position: absolute;
            top: 20px;
            left: 20px;
            right: 20px;
            bottom: 20px;
            background: var(--dark);
            border-radius: 8px;
            border: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }
        
        .switch-brand {
            font-size: 1.8rem;
            color: var(--primary);
            font-weight: bold;
        }
        
        .switch-name-3d {
            font-size: 1.3rem;
            color: var(--text);
            text-align: center;
            padding: 0 20px;
        }
        
        /* Hub Port Stilleri */
        .hub-port {
            border-color: #f59e0b !important;
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.2) 0%, rgba(245, 158, 11, 0.1) 100%) !important;
            position: relative;
        }

        .hub-port:hover {
            transform: scale(1.05);
            box-shadow: 0 5px 20px rgba(245, 158, 11, 0.6) !important;
            z-index: 10;
        }

        /* Hub visual diagram LED pulse animation */
        @keyframes hub-led-pulse {
            0%,100% { opacity:1; box-shadow:0 0 6px #10b981; }
            50%      { opacity:.55; box-shadow:0 0 12px #10b981; }
        }

        .hub-port .port-type {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%) !important;
            color: white !important;
        }

        .hub-icon {
         position: absolute;
    top: 6px;
    left: 6px; /* solda */
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
    color: white;
    width: 22px;
    height: 22px;
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.55rem;
    font-weight: 700;
    cursor: pointer;
    z-index: 6;
    box-shadow: 0 2px 6px rgba(0,0,0,0.35);
    transition: transform 0.12s ease;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
    padding: 0 2px;
}
.hub-icon:hover { transform: scale(1.12); }

/* Edit butonunu sağa al, hub ile çakışmasın */
.port-edit {
    position: absolute;
    top: 6px;
    right: 8px; /* biraz daha sağa */
    width: 28px;
    height: 28px;
    border-radius: 6px;
    background: rgba(255,255,255,0.06);
    color: var(--text);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    font-size: 0.9rem;
    border: 1px solid rgba(255,255,255,0.04);
    transition: all .15s ease;
    opacity: 0;
    transform: translateY(-4px);
    z-index: 5;
}
.port-item:hover .port-edit {
    opacity: 1;
    transform: translateY(0);
}
.port-edit:hover {
    background: rgba(59,130,246,0.12);
    color: #fff;
}

        /* Hub modal içerik */
        .hub-device-item {
            background: rgba(15, 23, 42, 0.5);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #f59e0b;
        }

        .hub-device-item:hover {
            background: rgba(56, 189, 248, 0.1);
        }
        
        .port-indicators {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            justify-content: center;
            padding: 0 20px;
        }
        
        .port-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--border);
            transition: all 0.3s ease;
        }
        
        .port-indicator.active {
            background: var(--success);
            box-shadow: 0 0 10px var(--success);
        }
        
        /* Port Grid */
        .ports-section {
            margin-top: 30px;
        }
        
        .ports-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .ports-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
            gap: 15px;
        }
        
        .port-item {
            background: var(--dark-light);
            border-radius: 10px;
            padding: 15px 10px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            border: 2px solid transparent;
        }
        
        .port-item:hover {
            transform: scale(1.05);
            z-index: 10;
            box-shadow: 0 5px 20px rgba(56, 189, 248, 0.5);
        }
        
        .port-item.connected {
            border-color: var(--success);
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.2) 0%, rgba(16, 185, 129, 0.1) 100%);
        }
        
        .port-item.ap { border-color: #3b82f6; }
        .port-item.iptv { border-color: #8b5cf6; }
        .port-item.fiber { border-color: #06b6d4; }
        .port-item.ethernet { border-color: #3b82f6; }
        .port-item.otomasyon { border-color: #f59e0b; }
        .port-item.device { border-color: #10b981; }
        .port-item.santral { border-color: #ec4899; }
        .port-item.server { border-color: #8b5cf6; }
        .port-item.hub { border-color: #f59e0b; }
        .port-item.kamera { border-color: #e53e3e; }
        .port-item.vlan { border-color: #dc2626; }
        
        .port-number {
            font-weight: bold;
            font-size: 1.1rem;
            margin-bottom: 8px;
            color: var(--text);
        }
        
        .port-type {
            font-size: 0.7rem;
            padding: 3px 8px;
            border-radius: 12px;
            background: var(--dark);
            color: var(--text-light);
            margin-bottom: 5px;
            display: inline-block;
        }
        
        .port-type.ethernet {
            background: #3b82f6;
            color: white;
        }

        .port-type.fiber {
            background: #8b5cf6;
            color: white;
        }

        .port-type.boş {
            background: #64748b;
            color: white;
        }

        .port-type.ap {
            background: #FF0000;
            color: white;
        }

        .port-type.iptv {
            background: #8b5cf6;
            color: white;
        }

        .port-type.device {
            background: #10b981;
            color: white;
        }

        .port-type.otomasyon {
            background: #f59e0b;
            color: white;
        }

        .port-type.santral {
            background: #ec4899;
            color: white;
        }

        .port-type.server {
            background: #8b5cf6;
            color: white;
        }

        .port-type.hub {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
        }
        
        .port-type.kamera {
            background: #e53e3e;
            color: white;
        }
        
        /* "VLAN X" type badge – red, indicating unknown/unrecognized VLAN */
        .port-type.vlan {
            background: #dc2626;
            color: white;
        }
        
        /* Port DOWN: red border indicator */
        .port-item.down {
            border-color: #ef4444 !important;
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(239, 68, 68, 0.07) 100%) !important;
        }
        .port-item.down .port-type {
            opacity: 0.8;
        }

        /* Port with active alarm: yellow/amber border indicator */
        .port-item.has-alarm {
            border-color: #f59e0b !important;
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.18) 0%, rgba(245, 158, 11, 0.08) 100%) !important;
            box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.35) !important;
        }

        /* Port never-seen: grey border — port is down but no device/MAC was ever detected */
        .port-item.never-seen {
            border-color: #475569 !important;
            background: linear-gradient(135deg, rgba(71, 85, 105, 0.15) 0%, rgba(71, 85, 105, 0.07) 100%) !important;
        }
        .port-item.never-seen .port-type {
            opacity: 0.7;
        }

        /* Port indicator dot: red tint when port is DOWN */
        .port-indicator.down {
            background: rgba(239, 68, 68, 0.45);
        }
        
        .port-device {
            font-size: 0.75rem;
            color: var(--text-light);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            margin-bottom: 5px;
        }

        .port-alias {
            font-size: 0.62rem;
            color: #38bdf8;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            margin-bottom: 3px;
            opacity: 0.85;
        }

        .port-rack {
            font-size: 0.7rem;
            color: var(--primary);
            font-weight: bold;
            background: rgba(59, 130, 246, 0.1);
            padding: 2px 6px;
            border-radius: 8px;
            display: inline-block;
        }

        /* Connection Indicator */
        .connection-indicator {
            position: absolute;
            bottom: 5px;
            right: 5px;
            color: #10b981;
            font-size: 0.7rem;
            background: rgba(16, 185, 129, 0.2);
            width: 18px;
            height: 18px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: help;
            z-index: 2;
        }

        .connection-indicator:hover {
            background: rgba(16, 185, 129, 0.4);
            color: white;
            transform: scale(1.1);
        }

        /* PoE aktif port — sağ üst köşe sarı bolt simgesi */
        .poe-badge {
            position: absolute;
            top: 5px;
            right: 5px;
            color: #f59e0b;
            font-size: 0.65rem;
            background: rgba(245, 158, 11, 0.2);
            width: 18px;
            height: 18px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: help;
            z-index: 2;
        }

        .poe-badge:hover {
            background: rgba(245, 158, 11, 0.45);
            color: white;
            transform: scale(1.15);
        }

        /* HUB portları için connection indicator */
        .hub-port .connection-indicator {
            color: #f59e0b;
            background: rgba(245, 158, 11, 0.2);
        }

        .hub-port .connection-indicator:hover {
            background: rgba(245, 158, 11, 0.4);
        }
        
        /* Buttons */
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s ease;
            font-size: 0.95rem;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(59, 130, 246, 0.4);
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success) 0%, #059669 100%);
            color: white;
        }
        
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(16, 185, 129, 0.4);
        }
        
        .btn-warning {
            background: linear-gradient(135deg, var(--warning) 0%, #d97706 100%);
            color: white;
        }
        
        .btn-warning:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(245, 158, 11, 0.4);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%);
            color: white;
        }
        
        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(239, 68, 68, 0.4);
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #64748b 0%, #475569 100%);
            color: white;
        }
        
        /* Modals */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(5px);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
        }
        
        .modal-overlay.active {
            opacity: 1;
            pointer-events: all;
        }
        
        .modal {
            background: linear-gradient(135deg, var(--dark-light) 0%, var(--dark) 100%);
            border-radius: 20px;
            padding: 30px;
            width: 90%;
            max-width: 500px;
            max-height: 90vh;
            overflow-y: auto;
            border: 2px solid rgba(56, 189, 248, 0.3);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            transform: translateY(20px);
            transition: transform 0.3s ease;
        }
        
        .modal-overlay.active .modal {
            transform: translateY(0);
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid rgba(56, 189, 248, 0.2);
        }
        
        .modal-title {
            font-size: 1.5rem;
            color: var(--text);
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-light);
            font-size: 1.8rem;
            cursor: pointer;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            transition: all 0.3s ease;
        }
        
        .modal-close:hover {
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger);
        }
        
        /* Form Elements */
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-light);
            font-weight: 600;
        }
        
        .form-control {
            width: 100%;
            padding: 12px 15px;
            background: rgba(15, 23, 42, 0.8);
            border: 2px solid rgba(56, 189, 248, 0.3);
            border-radius: 8px;
            color: var(--text);
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 20px rgba(56, 189, 248, 0.3);
        }
        
        .form-row {
            display: flex;
            gap: 15px;
        }
        
        .form-row .form-group {
            flex: 1;
        }
        
        /* Tabs */
        .tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 25px;
            background: var(--dark);
            padding: 5px;
            border-radius: 12px;
        }
        
        .tab-btn {
            flex: 1;
            padding: 12px;
            background: transparent;
            border: none;
            color: var(--text-light);
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.3s ease;
        }
        
        .tab-btn.active {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            box-shadow: 0 5px 15px rgba(59, 130, 246, 0.3);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Tooltip */
        .tooltip {
            position: absolute;
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid var(--primary);
            border-radius: 8px;
            padding: 15px;
            font-size: 0.85rem;
            color: var(--text);
            z-index: 1000;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.3s ease;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.5);
            min-width: 250px;
            max-width: 300px;
        }
        
        .tooltip-row {
            margin-bottom: 8px;
            display: flex;
        }
        
        .tooltip-label {
            width: 80px;
            color: var(--text-light);
            font-weight: bold;
            flex-shrink: 0;
        }
        
        .tooltip-value {
            flex: 1;
            color: var(--text);
            word-break: break-word;
        }
        
        /* Toast Notifications */
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1001;
        }
        
        .toast {
            background: var(--dark-light);
            border-radius: 10px;
            padding: 15px 20px;
            margin-bottom: 10px;
            border-left: 4px solid var(--primary);
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3);
            transform: translateX(100%);
            opacity: 0;
            animation: slideIn 0.3s ease forwards;
            max-width: 350px;
        }
        
        @keyframes slideIn {
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .toast.success { border-left-color: var(--success); }
        .toast.error { border-left-color: var(--danger); }
        .toast.warning { border-left-color: var(--warning); }
        .toast.info { border-left-color: var(--primary); }
        
        .toast-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }
        
        .toast-title {
            font-weight: bold;
            font-size: 0.95rem;
        }
        
        .toast-close {
            background: none;
            border: none;
            color: var(--text-light);
            cursor: pointer;
            font-size: 1.2rem;
        }
        
        /* Auto Backup Indicator */
        .backup-indicator {
            position: fixed;
            bottom: 20px;
            right: 100px;
            background: var(--dark-light);
            border-radius: 50%;
            width: 60px;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 2px solid var(--border);
            cursor: pointer;
            transition: all 0.3s ease;
            z-index: 100;
        }
        
        .backup-indicator:hover {
            border-color: var(--success);
            transform: scale(1.1);
        }
        
        .backup-indicator.active {
            border-color: var(--success);
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.5);
        }
        
        /* Responsive */
        @media (max-width: 1200px) {
            .racks-grid {
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            }
        }
        
        @media (max-width: 768px) {
            .racks-grid {
                grid-template-columns: 1fr;
            }
            
            .form-row {
                flex-direction: column;
            }
            
            .top-bar {
                flex-direction: column;
                align-items: stretch;
            }
            
            .search-box {
                max-width: 100%;
            }
            
            .ports-grid {
                grid-template-columns: repeat(auto-fill, minmax(80px, 1fr));
            }
        }
        
        /* Scrollbar Styling */
        ::-webkit-scrollbar {
            width: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--dark);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--primary);
            border-radius: 5px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--primary-dark);
        }
		
		/* küçük düzenle ikonu (port kartında sağ üstte) */
.port-edit {
    position: absolute;
    top: 6px;
    right: 6px;
    width: 28px;
    height: 28px;
    border-radius: 6px;
    background: rgba(255,255,255,0.06);
    color: var(--text);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    font-size: 0.9rem;
    border: 1px solid rgba(255,255,255,0.04);
    transition: all .15s ease;
    opacity: 0;
    transform: translateY(-4px);
}
.port-item:hover .port-edit {
    opacity: 1;
    transform: translateY(0);
}
.port-edit:hover {
    background: rgba(59,130,246,0.12);
    color: #fff;
}

/* Alarm Badge */
.alarm-badge {
    position: absolute;
    top: 8px;
    right: 8px;
    background: #ef4444;
    color: white;
    font-size: 11px;
    font-weight: bold;
    padding: 2px 6px;
    border-radius: 10px;
    min-width: 20px;
    text-align: center;
}

/* Alarm Modal Styles */
.alarm-modal-content {
    max-height: calc(90vh - 200px);
    overflow-y: auto;
    overflow-x: hidden;
}

/* Ensure modal is always centered and visible */
#port-alarms-modal.modal-overlay {
    overflow-y: auto;
    overflow-x: hidden;
}

#port-alarms-modal .modal {
    position: relative;
    margin: 50px auto;
}

.alarm-list-item {
    background: rgba(15, 23, 42, 0.5);
    border-radius: 8px;
    padding: 15px;
    margin-bottom: 10px;
    cursor: pointer;
    transition: all 0.3s;
    border-left: 4px solid transparent;
}

.alarm-list-item:hover {
    transform: translateX(5px);
    background: rgba(15, 23, 42, 0.7);
}

.alarm-list-item.critical {
    border-left-color: #ef4444;
}

.alarm-list-item.high {
    border-left-color: #f59e0b;
}

.alarm-list-item.medium {
    border-left-color: #fbbf24;
}

.alarm-list-item.low {
    border-left-color: #10b981;
}

.alarm-list-item .alarm-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}

.alarm-list-item .alarm-title-text {
    font-weight: 600;
    color: var(--text);
    font-size: 14px;
}

.alarm-list-item .alarm-severity-badge {
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
}

.alarm-severity-badge.critical { background: #ef4444; color: white; }
.alarm-severity-badge.high { background: #f59e0b; color: white; }
.alarm-severity-badge.medium { background: #fbbf24; color: #333; }
.alarm-severity-badge.low { background: #10b981; color: white; }

.alarm-list-item .alarm-message {
    color: var(--text-light);
    font-size: 13px;
    margin-bottom: 8px;
}

.alarm-list-item .alarm-meta {
    display: flex;
    gap: 15px;
    font-size: 12px;
    color: var(--text-light);
}
		
    </style>
</head>
<body>
    <!-- Loading Screen -->
    <div class="loading-screen" id="loading-screen">
        <div class="loader">
            <div class="loader-dot"></div>
            <div class="loader-dot"></div>
            <div class="loader-dot"></div>
        </div>
    </div>
    
    <!-- Sidebar Toggle -->
    <button class="sidebar-toggle" id="sidebar-toggle">
        <i class="fas fa-bars"></i>
    </button>
    
    <!-- Ana Sayfa Butonu - SAĞ ALT KÖŞE -->
    <button class="home-button" id="home-button" title="Ana Sayfaya Dön">
        <i class="fas fa-home"></i>
    </button>
    
    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="logo">
            <img src="logo.png" alt="CHAMADA" style="width:38px;height:38px;object-fit:contain;">
            <h1>CHAMADA NETWORK MANAGER</h1>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Dashboard</div>
            <button class="nav-item active" data-page="dashboard">
                <i class="fas fa-tachometer-alt"></i>
                <span>Dashboard</span>
            </button>
            <button class="nav-item" data-page="racks">
                <i class="fas fa-server"></i>
                <span>Rack Kabinler</span>
            </button>
            <button class="nav-item" data-page="switches">
                <i class="fas fa-network-wired"></i>
                <span>Switch'ler</span>
            </button>
            <button class="nav-item" data-page="topology">
                <i class="fas fa-project-diagram"></i>
                <span>Topoloji</span>
            </button>
            <button class="nav-item" data-page="port-alarms">
                <i class="fas fa-exclamation-triangle"></i>
                <span>Port Değişiklik Alarmları</span>
                <span id="alarm-badge" class="alarm-badge" style="display: none;">0</span>
            </button>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Raporlar</div>
            <button class="nav-item" data-page="reports" style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3);">
                <i class="fas fa-chart-bar"></i>
                <span>Raporlar</span>
            </button>
        </div>

        <?php if ($currentUser['role'] === 'admin'): ?>
        <div class="nav-section">
            <div class="nav-title">SNMP Admin</div>
            <button class="nav-item" id="nav-snmp-admin" onclick="window.open('pages/admin.php', '_blank')" style="background: rgba(139, 92, 246, 0.1); border: 1px solid rgba(139, 92, 246, 0.3);">
                <i class="fas fa-cogs"></i>
                <span>SNMP Admin Panel</span>
            </button>
        </div>
        <?php endif; ?>
        
        <div class="nav-section">
            <div class="nav-title">Kullanıcı</div>
            <div style="padding: 15px; background: rgba(15, 23, 42, 0.5); border-radius: 10px; margin-bottom: 10px;">
                <div style="font-size: 12px; color: var(--text-light); margin-bottom: 5px;">Giriş Yapan</div>
                <div style="font-size: 14px; color: var(--text); font-weight: 600;">
                    <i class="fas fa-user-circle"></i> <?php echo htmlspecialchars($currentUser['full_name']); ?>
                </div>
                <div style="font-size: 11px; color: var(--text-light); margin-top: 3px;">
                    <?php echo htmlspecialchars($currentUser['username']); ?>
                </div>
            </div>
            <?php if ($currentUser['role'] === 'admin'): ?>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 10px;">
                <a href="index.php" title="PRESTİGE sistemine git" style="display: flex; flex-direction: column; align-items: center; gap: 4px; padding: 10px 6px; background: rgba(37, 99, 235, 0.15); border: 1px solid rgba(59, 130, 246, 0.4); border-radius: 10px; text-decoration: none; color: #60a5fa; font-size: 11px; font-weight: 600; transition: all 0.2s; letter-spacing: 0.5px;">
                    <i class="fas fa-building" style="font-size: 18px;"></i>
                    PRESTİGE
                </a>
                <a href="pages/maintenance.php" title="GİRNE sistemine git" style="display: flex; flex-direction: column; align-items: center; gap: 4px; padding: 10px 6px; background: rgba(217, 119, 6, 0.15); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 10px; text-decoration: none; color: #fbbf24; font-size: 11px; font-weight: 600; transition: all 0.2s; letter-spacing: 0.5px;">
                    <i class="fas fa-city" style="font-size: 18px;"></i>
                    GİRNE
                </a>
            </div>
            <?php endif; ?>
            <button class="nav-item" onclick="window.location.href='logout.php'" style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);">
                <i class="fas fa-sign-out-alt"></i>
                <span>Çıkış Yap</span>
            </button>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content" id="main-content">
        <!-- Dashboard Page -->
        <div class="page-content active" id="page-dashboard">
            <div class="top-bar">
                <div class="page-title">
                    <i class="fas fa-tachometer-alt"></i>
                    <span>Dashboard</span>
                </div>
                <div class="search-box">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" class="search-input" id="dashboard-search" placeholder="Cihaz adı, MAC, IP, Switch ara...">
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card" style="border-color:rgba(59,130,246,0.4);">
                    <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;">
                        <i class="fas fa-server stat-icon" style="color:#3b82f6;font-size:2rem;margin:0;"></i>
                        <span style="font-size:0.7rem;padding:3px 8px;border-radius:12px;background:rgba(59,130,246,0.15);color:#93c5fd;border:1px solid rgba(59,130,246,0.3);">SNMP</span>
                    </div>
                    <div class="stat-value" id="stat-total-switches" style="font-size:2.4rem;">0</div>
                    <div class="stat-label">Toplam Switch</div>
                </div>
                <div class="stat-card" style="border-color:rgba(16,185,129,0.4);">
                    <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;">
                        <i class="fas fa-plug stat-icon" style="color:#10b981;font-size:2rem;margin:0;"></i>
                        <span style="font-size:0.7rem;padding:3px 8px;border-radius:12px;background:rgba(16,185,129,0.15);color:#6ee7b7;border:1px solid rgba(16,185,129,0.3);">AKTİF</span>
                    </div>
                    <div class="stat-value" id="stat-active-ports" style="font-size:2.4rem;">0</div>
                    <div class="stat-label"><span id="stat-total-ports-label">0</span> Port / <span id="stat-active-ports-label">0</span> Aktif Port</div>
                </div>
                <div class="stat-card" style="border-color:rgba(245,158,11,0.4);">
                    <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;">
                        <i class="fas fa-cube stat-icon" style="color:#f59e0b;font-size:2rem;margin:0;"></i>
                        <span style="font-size:0.7rem;padding:3px 8px;border-radius:12px;background:rgba(245,158,11,0.15);color:#fcd34d;border:1px solid rgba(245,158,11,0.3);">KABİN</span>
                    </div>
                    <div class="stat-value" id="stat-total-racks" style="font-size:2.4rem;">0</div>
                    <div class="stat-label">Rack Kabin</div>
                </div>
                <div class="stat-card" style="border-color:rgba(139,92,246,0.4);">
                    <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;">
                        <i class="fas fa-th-large stat-icon" style="color:#8b5cf6;font-size:2rem;margin:0;"></i>
                        <span style="font-size:0.7rem;padding:3px 8px;border-radius:12px;background:rgba(139,92,246,0.15);color:#c4b5fd;border:1px solid rgba(139,92,246,0.3);">PANEL</span>
                    </div>
                    <div class="stat-value" id="stat-total-panels" style="font-size:2.4rem;">0</div>
                    <div class="stat-label">Patch Panel</div>
                </div>
            </div>
            
            <div class="racks-grid" id="dashboard-racks">
                <!-- Rack cards will be loaded here -->
            </div>
        </div>
        
        <!-- Racks Page -->
        <div class="page-content" id="page-racks">
            <div class="top-bar">
                <div class="page-title">
                    <i class="fas fa-server"></i>
                    <span>Rack Kabinler</span>
                </div>
                <div class="search-box">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" class="search-input page-search" id="racks-search" placeholder="Rack, Switch, MAC, IP ara...">
                </div>
            </div>
            
            <div class="racks-grid" id="racks-container">
                <!-- Rack cards with patch panels will be loaded here -->
            </div>
        </div>
        
        <!-- Switches Page -->
        <div class="page-content" id="page-switches">
            <div class="top-bar">
                <div class="page-title">
                    <i class="fas fa-network-wired"></i>
                    <span>Switch'ler</span>
                </div>
                <div class="search-box">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" class="search-input page-search" id="switches-search" placeholder="Switch, MAC, IP, Cihaz ara...">
                </div>
            </div>
            
            <div class="tabs">
                <button class="tab-btn active" data-tab="all-switches">Tümü</button>
                <button class="tab-btn" data-tab="online-switches">Online</button>
                <button class="tab-btn" data-tab="offline-switches">Offline</button>
            </div>
            
            <div class="racks-grid" id="switches-container">
                <!-- Switch cards will be loaded here -->
            </div>
        </div>
        
        <!-- Switch Detail Panel -->
        <div class="detail-panel" id="detail-panel" style="display: none;">
            <div class="detail-header">
                <div>
                    <h2 id="switch-detail-name">Switch Adı</h2>
                    <div style="display: flex; gap: 20px; margin-top: 10px; color: var(--text-light);">
                        <span id="switch-detail-brand"></span>
                        <span id="switch-detail-status"></span>
                        <span id="switch-detail-ports"></span>
                        <span id="switch-detail-poe" style="display:none;"></span>
                    </div>
                </div>
                <div style="display: flex; gap: 10px;">
                    <a id="detail-fullpage-link" class="btn btn-secondary btn-close-overlay" href="#" target="_blank" style="text-decoration:none;">
                        <i class="fas fa-external-link-alt"></i> Tam Sayfada Aç
                    </a>
                    <button class="btn btn-secondary btn-close-overlay" onclick="hideDetailPanel()">
                        <i class="fas fa-times"></i> Kapat
                    </button>
                    <button class="btn btn-secondary" onclick="window.open('pages/admin.php', '_blank')">
                        <i class="fas fa-cogs"></i> Yönetim Paneli
                    </button>
                </div>
            </div>
            
            <!-- Switch Sağlık Bilgi Barı – snmp_switch_health.php ile doldurulur -->
            <div id="switch-health-bar" style="display:none;">
                <span id="switch-health-loading">
                    <i class="fas fa-circle-notch fa-spin"></i> Sistem bilgileri alınıyor…
                </span>
            </div>
            
            <div class="switch-visual">
                <div class="switch-3d" id="switch-3d">
                    <div class="switch-front">
                        <div class="switch-brand" id="switch-brand-3d">Cisco</div>
                        <div class="switch-name-3d" id="switch-name-3d">SW2 -OTEL</div>
                        <div class="port-indicators" id="port-indicators">
                            <!-- Port indicators will be generated here -->
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="ports-section">
                <div class="ports-header">
                    <h3>Port Bağlantıları</h3>
                </div>
                
                <div class="ports-grid" id="detail-ports-grid">
                    <!-- Port grid will be loaded here -->
                </div>
            </div>
        </div>
        
        <!-- Topology Page -->
        <div class="page-content" id="page-topology">
            <div class="top-bar">
                <div class="page-title">
                    <i class="fas fa-project-diagram"></i>
                    <span>Network Topolojisi &amp; Kablo İzleme</span>
                </div>
                <div class="search-box">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" class="search-input page-search" id="topology-search" placeholder="Switch, panel, port ara..." oninput="filterTopologyNodes(this.value)">
                </div>
            </div>

            <div class="detail-panel" style="padding:0; overflow:hidden;">
                <!-- Toolbar -->
                <div style="display:flex; align-items:center; gap:10px; padding:14px 20px; border-bottom:1px solid var(--border); flex-wrap:wrap;">
                    <button id="topo-btn-all" class="btn btn-primary" style="font-size:13px; padding:6px 14px;" onclick="topoSetView('all')"><i class="fas fa-sitemap"></i> Tümü</button>
                    <button class="btn" style="font-size:13px; padding:6px 14px; background:var(--border); color:var(--text);" onclick="topoReset()"><i class="fas fa-redo"></i> Sıfırla</button>
                    <!-- Rack filter -->
                    <select id="topo-rack-select" onchange="topoFilterRack(this.value)"
                        style="padding:6px 12px; border:1px solid var(--border); border-radius:8px; background:var(--dark); color:var(--text); font-size:13px; min-width:160px;">
                        <option value="">Tüm Rack'ler</option>
                    </select>
                    <div id="topo-trace-hint" style="display:none;"></div>
                </div>

                <!-- Canvas area -->
                <div style="position:relative; overflow:auto; background:var(--dark);" id="topo-scroll-wrap">
                    <canvas id="topo-canvas" style="display:block;"></canvas>
                </div>

                <!-- Trace result panel -->
                <div id="topo-trace-panel" style="display:none; padding:16px 20px; border-top:1px solid var(--border); background:rgba(139,92,246,.05);">
                    <h4 style="color:#c4b5fd; margin-bottom:10px; font-size:14px;"><i class="fas fa-route"></i> Fiziksel Kablo Yolu</h4>
                    <div id="topo-trace-result" style="display:flex; align-items:center; flex-wrap:wrap; gap:6px; font-size:13px;"></div>
                </div>
            </div>
        </div>
        
        <!-- Port Alarms Page -->
        <div class="page-content" id="page-port-alarms">
            <div class="top-bar">
                <div class="page-title">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>Port Değişiklik Alarmları</span>
                </div>
                <div class="search-box">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" class="search-input page-search" id="alarms-search" placeholder="Cihaz adı, MAC, IP, Switch ara...">
                </div>
            </div>
            
            <!-- Port Alarms Component (same-origin trusted PHP file, no sandbox needed) -->
            <iframe src="pages/port_alarms.php" 
                    style="width: 100%; height: calc(100vh - 150px); border: none; border-radius: 15px; background: var(--dark);"
                    onload="this.style.display='block'"
                    onerror="this.innerHTML='<div style=padding:20px;text-align:center;color:red;>Error loading port alarms page</div>'">
            </iframe>
        </div>
        
        <!-- Device Import Page -->
        <div class="page-content" id="page-device-import">
            <div class="top-bar">
                <div class="page-title">
                    <i class="fas fa-file-import"></i>
                    <span>Device Import - MAC Address Registry</span>
                </div>
                <div class="search-box">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" class="search-input page-search" id="device-import-search" placeholder="Cihaz adı, MAC, IP, Switch ara...">
                </div>
            </div>
            
            <!-- Device Import Component (same-origin trusted PHP file, no sandbox needed) -->
            <iframe src="pages/device_import.php" 
                    style="width: 100%; height: calc(100vh - 150px); border: none; border-radius: 15px; background: var(--dark);"
                    onload="this.style.display='block'"
                    onerror="this.innerHTML='<div style=padding:20px;text-align:center;color:red;>Error loading device import page</div>'">
            </iframe>
        </div>

        <!-- Reports Page -->
        <div class="page-content" id="page-reports">
            <!-- Reports Component (same-origin trusted PHP file, no sandbox needed) -->
            <iframe src="pages/reports.php" 
                    style="width: 100%; height: calc(100vh - 60px); border: none; border-radius: 15px; background: var(--dark);"
                    onload="this.style.display='block'"
                    onerror="this.innerHTML='<div style=padding:20px;text-align:center;color:red;>Error loading reports page</div>'">
            </iframe>
        </div>
    </div>
    
    <!-- Toast Container -->
    <div class="toast-container" id="toast-container"></div>
    
    <!-- Modals -->
    <!-- Switch Modal -->
    <div class="modal-overlay" id="switch-modal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Yeni Switch Ekle</h3>
                <button class="modal-close" id="close-switch-modal">&times;</button>
            </div>
            <form id="switch-form">
                <input type="hidden" id="switch-id">
                <input type="hidden" id="switch-is-core" value="0">
                <input type="hidden" id="switch-is-virtual" value="0">
                <div class="form-group">
                    <label class="form-label">Switch Adı</label>
                    <input type="text" id="switch-name" class="form-control" placeholder="Ör: SW2 -OTEL" required>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Marka</label>
                        <select id="switch-brand" class="form-control" required>
                            <option value="">Seçiniz</option>
                            <option value="Cisco">Cisco</option>
                            <option value="HP">HP</option>
                            <option value="Juniper">Juniper</option>
                            <option value="Aruba">Aruba</option>
                            <option value="MikroTik">MikroTik</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Model</label>
                        <input type="text" id="switch-model" class="form-control" placeholder="Ör: Catalyst 9500">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Port Sayısı</label>
                        <select id="switch-ports" class="form-control" required>
                            <option value="24">24 Port (20 Ethernet + 4 Fiber)</option>
                            <option value="48" selected>48 Port (44 Ethernet + 4 Fiber)</option>
                            <option value="52">52 Port (48 Ethernet + 4 Fiber)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Durum</label>
                        <select id="switch-status" class="form-control" required>
                            <option value="online">Çevrimiçi</option>
                            <option value="offline">Çevrimdışı</option>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label">Rack Kabin *</label>
                    <select id="switch-rack" class="form-control" required></select>
                </div>

                <div class="form-group">
                    <label class="form-label">Rack Slot Pozisyonu</label>
                    <select id="switch-position" class="form-control">
                        <option value="">Önce Rack Seçin</option>
                    </select>
                    <small style="color: var(--text-light); display: block; margin-top: 5px;">
                        <i class="fas fa-info-circle"></i> Seçmezseniz otomatik yerleştirilecek
                    </small>
                </div>

                <div class="form-group">
                    <label class="form-label">IP Adresi</label>
                    <input type="text" id="switch-ip" class="form-control" placeholder="Ör: 192.168.1.1">
                </div>
                <div style="display: flex; gap: 10px; margin-top: 30px;">
                    <button type="button" class="btn btn-secondary" style="flex: 1;" id="cancel-switch-btn">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex: 1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Rack Modal -->
    <div class="modal-overlay" id="rack-modal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Yeni Rack Ekle</h3>
                <button class="modal-close" id="close-rack-modal">&times;</button>
            </div>
            <form id="rack-form">
                <input type="hidden" id="rack-id">
                <div class="form-group">
                    <label class="form-label">Rack Adı</label>
                    <input type="text" id="rack-name" class="form-control" placeholder="Ör: Ana Rack #1" required>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Konum</label>
                        <input type="text" id="rack-location" class="form-control" placeholder="Ör: Ana Sistem Odası">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Slot Sayısı</label>
                        <input type="number" id="rack-slots" class="form-control" min="1" max="100" value="42">
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label">Açıklama</label>
                    <textarea id="rack-description" class="form-control" rows="3" placeholder="Rack hakkında açıklama"></textarea>
                </div>
                <div style="display: flex; gap: 10px; margin-top: 30px;">
                    <button type="button" class="btn btn-secondary" style="flex: 1;" id="cancel-rack-btn">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex: 1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Patch Panel Modal -->
    <div class="modal-overlay" id="patch-panel-modal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title" id="patch-panel-title">Patch Panel Ekle</h3>
                <button class="modal-close" id="close-patch-panel-modal">&times;</button>
            </div>
            <form id="patch-panel-form">
                <input type="hidden" id="patch-panel-id">
                <input type="hidden" id="patch-panel-rack-id">
                
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Rack</label>
                        <select id="panel-rack-select" class="form-control" required>
                            <option value="">Rack Seçin</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Panel Harfi</label>
                        <select id="panel-letter" class="form-control" required>
                            <option value="">Harf Seçin</option>
                            <option value="A">A</option>
                            <option value="B">B</option>
                            <option value="C">C</option>
                            <option value="D">D</option>
                            <option value="E">E</option>
                            <option value="F">F</option>
                            <option value="G">G</option>
                            <option value="H">H</option>
                            <option value="I">I</option>
                            <option value="J">J</option>
                            <option value="K">K</option>
                            <option value="L">L</option>
                            <option value="M">M</option>
                            <option value="N">N</option>
                            <option value="O">O</option>
                            <option value="P">P</option>
                            <option value="Q">Q</option>
                            <option value="R">R</option>
                            <option value="S">S</option>
                            <option value="T">T</option>
                            <option value="U">U</option>
                            <option value="V">V</option>
                            <option value="W">W</option>
                            <option value="X">X</option>
                            <option value="Y">Y</option>
                            <option value="Z">Z</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Port Sayısı</label>
                        <select id="panel-port-count" class="form-control" required>
                            <option value="24" selected>24 Port</option>
                            <option value="48">48 Port</option>
                            <option value="12">12 Port</option>
                            <option value="6">6 Port</option>
                        </select>
                    </div>
                 <div class="form-group">
                    <label class="form-label">Rack Slot Pozisyonu *</label>
                    <select id="panel-position" class="form-control" required disabled>
                        <option value="">Önce Rack Seçin</option>
                    </select>
                </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Açıklama</label>
                    <input type="text" id="panel-description" class="form-control" 
                           placeholder="Ör: Ana Patch Panel, Fiber Giriş">
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 30px;">
                    <button type="button" class="btn btn-secondary" style="flex: 1;" 
                            id="cancel-patch-panel-btn">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex: 1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Rack Detail Modal -->
    <div class="modal-overlay" id="rack-detail-modal">
        <div class="modal" style="max-width: 800px;">
            <div class="modal-header">
                <h3 class="modal-title" id="rack-detail-title">Rack Detayı</h3>
                <button class="modal-close" id="close-rack-detail-modal">&times;</button>
            </div>
            <div id="rack-detail-content">
                <!-- İçerik JavaScript ile doldurulacak -->
            </div>
        </div>
    </div>

    <!-- Panel Detail Modal -->
    <div class="modal-overlay" id="panel-detail-modal">
        <div class="modal" style="max-width: 800px;">
            <div class="modal-header">
                <h3 class="modal-title" id="panel-detail-title">Panel Detayı</h3>
                <button class="modal-close" id="close-panel-detail-modal">&times;</button>
            </div>
            <div id="panel-detail-content">
                <!-- İçerik JavaScript ile doldurulacak -->
            </div>
        </div>
    </div>

    <!-- Rack Device (Hub SW / Server) Detail Modal -->
    <div class="modal-overlay" id="rd-device-modal">
        <div class="modal" style="max-width: 800px;">
            <div class="modal-header" id="rd-device-modal-header">
                <h3 class="modal-title" id="rd-device-modal-title">Cihaz Detayı</h3>
                <button class="modal-close" id="close-rd-device-modal">&times;</button>
            </div>
            <div id="rd-device-modal-content">
                <!-- İçerik JavaScript ile doldurulacak -->
            </div>
        </div>
    </div>

    <!-- Fiber Panel Modal -->
    <div class="modal-overlay" id="fiber-panel-modal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title" id="fiber-panel-title">Fiber Panel Ekle</h3>
                <button class="modal-close" id="close-fiber-panel-modal">&times;</button>
            </div>
            <form id="fiber-panel-form">
                <input type="hidden" id="fiber-panel-rack-id">
                
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Rack</label>
                        <select id="fiber-panel-rack-select" class="form-control" required>
                            <option value="">Rack Seçin</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Panel Harfi</label>
                        <select id="fiber-panel-letter" class="form-control" required>
                            <option value="">Harf Seçin</option>
                            <option value="A">A</option>
                            <option value="B">B</option>
                            <option value="C">C</option>
                            <option value="D">D</option>
                            <option value="E">E</option>
                            <option value="F">F</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Fiber Sayısı</label>
                        <select id="fiber-count" class="form-control" required>
                            <option value="12">12 Fiber</option>
                            <option value="24">24 Fiber</option>
                            <option value="48">48 Fiber</option>
                            <option value="96">96 Fiber</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Rack Slot Pozisyonu</label>
                        <select id="fiber-panel-position" class="form-control" required disabled>
                            <option value="">Önce Rack Seçin</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Açıklama</label>
                    <input type="text" id="fiber-panel-description" class="form-control" 
                           placeholder="Ör: Ana Fiber Giriş, ODF Paneli">
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 30px;">
                    <button type="button" class="btn btn-secondary" style="flex: 1;" 
                            id="cancel-fiber-panel-btn">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex: 1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- SNMP Data Viewer Modal -->

    <!-- Backup/Restore Modal -->
    <div class="modal-overlay" id="backup-modal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Yedekleme ve Geri Yükleme</h3>
                <button class="modal-close" id="close-backup-modal">&times;</button>
            </div>
            <div class="tabs">
                <button class="tab-btn active" data-backup-tab="backup">Yedekle</button>
                <button class="tab-btn" data-backup-tab="restore">Geri Yükle</button>
                <button class="tab-btn" data-backup-tab="history">Geçmiş</button>
            </div>
            <div id="backup-content">
                <!-- Content will be loaded by JavaScript -->
            </div>
        </div>
    </div>

    <!-- Hub Port Modal'ı -->
    <div class="modal-overlay" id="hub-modal">
        <div class="modal" style="max-width: 760px; width: 95%;">
            <div class="modal-header">
                <h3 class="modal-title" id="hub-modal-title">Hub Port Yönetimi</h3>
                <button class="modal-close" id="close-hub-modal">&times;</button>
            </div>
            <div id="hub-content">
                <!-- Hub bilgileri buraya yüklenecek -->
            </div>
        </div>
    </div>

    <!-- Hub Port Ekleme/Değiştirme Modal'ı -->
    <div class="modal-overlay" id="hub-edit-modal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Hub Port Ayarları</h3>
                <button class="modal-close" id="close-hub-edit-modal">&times;</button>
            </div>
            <form id="hub-form">
                <input type="hidden" id="hub-switch-id">
                <input type="hidden" id="hub-port-number">
                
                <div class="form-group">
                    <label class="form-label">Hub Adı</label>
                    <input type="text" id="hub-name" class="form-control" 
                           placeholder="Ör: Kat-3 Hub, Lobby Hub">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Hub Tipi</label>
                    <select id="hub-type" class="form-control">
                        <option value="ETHERNET">Ethernet Hub</option>
                        <option value="FIBER">Fiber Hub</option>
                        <option value="POE">PoE Hub</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Bağlı Cihazlar</label>
                    <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px;">
                        <div id="hub-devices-list">
                            <!-- Dinamik olarak eklenecek -->
                        </div>
                        <button type="button" class="btn btn-primary" id="add-hub-device" 
                                style="width: 100%; margin-top: 10px;">
                            <i class="fas fa-plus"></i> Cihaz Ekle
                        </button>
                        <button type="button" class="btn btn-primary" id="add-multiple-devices" 
                                style="width: 100%; margin-top: 10px;">
                            <i class="fas fa-plus-circle"></i> Çoklu Cihaz Ekle
                        </button>
                    </div>
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 30px;">
                    <button type="button" class="btn btn-danger" style="flex: 1;" id="remove-hub-btn">
                        <i class="fas fa-trash"></i> Hub'ı Kaldır
                    </button>
                    <button type="button" class="btn btn-secondary" style="flex: 1;" 
                            id="cancel-hub-btn">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex: 1;">Kaydet</button>
                </div>
            </form>
        </div>
    </div>

    <!-- ============================================
    GÜNCELLENMİŞ PORT MODAL - Connection Alanı Korunuyor
    ============================================ -->
    <div class="modal-overlay" id="port-modal">
        <div class="modal" style="max-width: 600px;">
            <div class="modal-header">
                <h3 class="modal-title" id="port-modal-title">Port Bağlantısı</h3>
                <button class="modal-close" id="close-port-modal">&times;</button>
            </div>
            <form id="port-form">
                <input type="hidden" id="port-switch-id">
                <input type="hidden" id="port-number">
                <input type="hidden" id="port-switch-rack-id">
                
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Port Numarası</label>
                        <input type="text" id="port-no-display" class="form-control" readonly>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Bağlantı Türü</label>
                        <select id="port-type" class="form-control">
                            <option value="BOŞ">BOŞ</option>
                            <option value="DEVICE">DEVICE</option>
                            <option value="SERVER">SERVER</option>
                            <option value="AP">AP</option>
                            <option value="KAMERA">KAMERA</option>
                            <option value="IPTV">IPTV</option>
                            <option value="OTOMASYON">OTOMASYON</option>
                            <option value="SANTRAL">SANTRAL</option>
                            <option value="FIBER">FIBER</option>
                            <option value="ETHERNET">ETHERNET</option>
                            <option value="HUB">HUB</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label" style="display:flex;align-items:center;gap:8px;">
                        Cihaz Adı/Açıklama
                        <span id="modal-vlan-badge" style="display:none;font-size:11px;font-weight:600;padding:2px 8px;border-radius:10px;background:#0d6efd;color:#fff;letter-spacing:.5px;"></span>
                    </label>
                    <input type="text" id="port-device" class="form-control" placeholder="Ör: PK10, Lobby ONU">
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">IP Adresi</label>
                        <input type="text" id="port-ip" class="form-control" placeholder="Ör: 172.18.50.9">
                    </div>
                    <div class="form-group">
                        <label class="form-label">MAC Adresi</label>
                        <input type="text" id="port-mac" class="form-control" placeholder="Ör: f8:a2:6d:f0:82:a8">
                    </div>
                </div>
                
                <!-- ÖNEMLİ: CONNECTION ALANI - HER ZAMAN GÖRÜNÜR -->
                <div class="form-group" id="connection-info-group">
                    <label class="form-label">
                        <i class="fas fa-link"></i> Connection Bilgisi
                        <small style="color: var(--text-light); font-weight: normal;">
                            (Excel'den gelen ek bağlantı bilgileri)
                        </small>
                    </label>
                    <textarea id="port-connection-info" class="form-control" rows="3" 
                              placeholder="Ruby 3232, ONU, vb. gibi ek bağlantı bilgileri"></textarea>
                    <small style="color: var(--text-light); display: block; margin-top: 5px;">
                        <i class="fas fa-info-circle"></i> Bu alan panel bilgisi girilse bile korunur
                    </small>
                </div>
                
                <!-- PANEL BAĞLANTISI -->
                <div class="form-group" style="border-top: 2px solid var(--border); padding-top: 20px; margin-top: 20px;">
                    <label class="form-label">
                        <i class="fas fa-th-large"></i> Panel Bağlantısı (Opsiyonel)
                    </label>
                    
                    <!-- Panel Tipi Seçimi -->
                    <div class="form-row" style="margin-bottom: 10px;">
                        <div class="form-group">
                            <label class="form-label" style="font-size: 0.9rem;">Panel Tipi</label>
                            <select id="panel-type-select" class="form-control">
                                <option value="">Panel Tipi Seçin</option>
                                <option value="patch">Patch Panel</option>
                                <option value="fiber">Fiber Panel</option>
                            </select>
                        </div>
                    </div>
                    
                    <!-- Panel ve Port Seçimi -->
                    <div class="form-row">
                        <div class="form-group" style="flex: 2;">
                            <select id="patch-panel-select" class="form-control" disabled>
                                <option value="">Önce panel tipi seçin</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <input type="number" id="patch-port-number" class="form-control" 
                                   placeholder="Port No" min="1" max="48" disabled>
                        </div>
                    </div>
                    
                    <!-- Bağlantı Önizlemesi -->
                    <div style="margin-top: 10px;" id="panel-connection-preview">
                        <div id="patch-display" style="color: var(--primary); font-weight: bold; font-size: 1.1rem;"></div>
                        <small style="color: var(--text-light); display: block; margin-top: 5px;">
                            <i class="fas fa-filter"></i> Sadece bu switch'in bulunduğu rack'teki paneller listelenir
                        </small>
                    </div>
                    
                    <!-- Fiber Kuralları Uyarısı -->
                    <div id="fiber-warning" style="display: none; margin-top: 10px; padding: 10px; background: rgba(239, 68, 68, 0.1); border-left: 4px solid #ef4444; border-radius: 5px;">
                        <small style="color: #ef4444;">
                            <i class="fas fa-exclamation-triangle"></i> 
                            <strong>Dikkat:</strong> Fiber paneller sadece fiber portlara bağlanabilir (son 4 port)
                        </small>
                    </div>
                    
                    <div id="patch-warning" style="display: none; margin-top: 10px; padding: 10px; background: rgba(245, 158, 11, 0.1); border-left: 4px solid #f59e0b; border-radius: 5px;">
                        <small style="color: #f59e0b;">
                            <i class="fas fa-exclamation-triangle"></i> 
                            <strong>Dikkat:</strong> Patch paneller fiber portlara bağlanamaz
                        </small>
                    </div>
                </div>
                
                <!-- CORE SWITCH BAĞLANTISI (FIBER PORTLAR İÇİN) -->
                <div class="form-group" id="core-switch-connection-group" style="border-top: 2px solid #fbbf24; padding-top: 20px; margin-top: 20px; display:none;">
                    <label class="form-label" style="color:#fbbf24;">
                        <i class="fas fa-server"></i> Core Switch Bağlantısı <small style="color:var(--text-light);font-weight:normal;">(Opsiyonel)</small>
                    </label>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label" style="font-size:0.9rem;">Core Switch</label>
                            <select id="core-switch-select" class="form-control">
                                <option value="">Core Switch Seç</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label" style="font-size:0.9rem;">Port (TwentyFiveGigE)</label>
                            <select id="core-switch-port-select" class="form-control" disabled>
                                <option value="">Önce switch seçin</option>
                            </select>
                        </div>
                    </div>
                    <div id="core-switch-preview" style="margin-top:8px; padding:8px; background:rgba(251,191,36,0.08); border:1px solid rgba(251,191,36,0.3); border-radius:6px; display:none; font-size:0.85rem; color:#fbbf24;">
                        <i class="fas fa-link"></i> <span id="core-switch-preview-text"></span>
                    </div>
                    <small style="display:block; margin-top:6px; color:var(--text-light);">
                        <i class="fas fa-info-circle"></i> Core switch bağlantısı "Connection Bilgisi" alanına otomatik yazılır
                    </small>
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 30px;">
                    <button type="button" class="btn btn-danger" style="flex: 1;" id="port-clear-btn">
                        <i class="fas fa-trash"></i> Boşa Çek
                    </button>
                    <button type="button" class="btn btn-secondary" style="flex: 1;" id="cancel-port-btn">İptal</button>
                    <button type="submit" class="btn btn-primary" style="flex: 1;">
                        <i class="fas fa-save"></i> Kaydet
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- SNMP Port Detail Modal -->
    <div class="modal-overlay" id="snmp-port-detail-modal">
        <div class="modal" style="max-width:860px; max-height:90vh; overflow-y:auto;">
            <div class="modal-header" style="position:sticky;top:0;background:var(--dark-light);z-index:1;">
                <div>
                    <h3 class="modal-title" id="snmp-port-detail-title"><i class="fas fa-network-wired"></i> Port Detayı</h3>
                    <div id="snmp-port-detail-subtitle" style="font-size:0.8rem;color:var(--text-light);margin-top:4px;"></div>
                </div>
                <button class="modal-close" id="close-snmp-port-detail-modal">&times;</button>
            </div>
            <div id="snmp-port-detail-content" style="padding:20px;">
                <div style="text-align:center;padding:40px;"><i class="fas fa-spinner fa-spin" style="font-size:2rem;color:var(--primary);"></i><div style="margin-top:12px;color:var(--text-light);">SNMP verisi çekiliyor...</div></div>
            </div>
        </div>
    </div>

    <!-- Port Alarms Modal -->
    <div class="modal-overlay" id="port-alarms-modal">
        <div class="modal" style="max-width: 900px;">
            <div class="modal-header">
                <div>
                    <h3 class="modal-title"><i class="fas fa-exclamation-triangle"></i> Port Değişiklik Alarmları</h3>
                    <div id="alarm-severity-counts"></div>
                </div>
                <button class="modal-close" id="close-alarms-modal">&times;</button>
            </div>
            <div class="alarm-modal-content">
                <div style="margin-bottom: 15px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
                    <button class="btn btn-primary alarm-filter-btn" data-filter="all" style="flex: 1; min-width: 120px;">
                        <i class="fas fa-list"></i> Tümü
                    </button>
                    <button class="btn btn-secondary alarm-filter-btn" data-filter="mac_moved" style="flex: 1; min-width: 120px;">
                        <i class="fas fa-exchange-alt"></i> MAC Taşındı
                    </button>
                    <button class="btn btn-secondary alarm-filter-btn" data-filter="vlan_changed" style="flex: 1; min-width: 120px;">
                        <i class="fas fa-network-wired"></i> VLAN Değişti
                    </button>
                    <button class="btn btn-secondary alarm-filter-btn" data-filter="description_changed" style="flex: 1; min-width: 120px;">
                        <i class="fas fa-edit"></i> Açıklama Değişti
                    </button>
                    <button class="btn" id="bulk-close-alarms-btn" style="flex: 1; min-width: 140px; background: #27ae60; color: white; border: none; cursor: pointer;" onclick="bulkAcknowledgeAllAlarms()">
                        <i class="fas fa-check-double"></i> Tümünü Kapat
                    </button>
                </div>
                <div id="alarms-list-container">
                    <div style="text-align: center; padding: 40px; color: var(--text-light);">
                        <i class="fas fa-spinner fa-spin" style="font-size: 32px; margin-bottom: 15px;"></i>
                        <p>Alarmlar yükleniyor...</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        
		function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"'`]/g, function (s) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '`': '&#96;'
        }[s];
    });
}

function maskIPs(text) {
    if (!text) return text;
    return text.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '***');
}
        let switches = [];
        let portConnections = {};
        let racks = [];
        let patchPanels = [];
        let fiberPanels = [];
        let rackDevices = [];
        let hubSwPortConnections = [];
        let snmpDevices = [];
        let selectedSwitch = null;
        let selectedRack = null;
        let backupHistory = [];
        let lastBackupTime = null;
        let tooltip = null;

        // ============================================
        // YENİ GLOBAL DEĞİŞKENLER
        // ============================================
        let patchPorts = {}; // Panel ID'sine göre portlar
        let fiberPorts = {}; // Fiber panel portları için

        // DOM elementleri
        const loadingScreen = document.getElementById('loading-screen');
        const sidebar = document.getElementById('sidebar');
        const sidebarToggle = document.getElementById('sidebar-toggle');
        const homeButton = document.getElementById('home-button');
        const mainContent = document.getElementById('main-content');
        const toastContainer = document.getElementById('toast-container');
        // ============================================
        // PANEL TARAFINDAN DÜZENLEME SİSTEMİ FONKSİYONLARI
        // ============================================

        // Panel port düzenleme modal'ı
        function openPanelPortEditModal(panelId, portNumber, panelType) {
            const panel = panelType === 'patch' 
                ? patchPanels.find(p => p.id == panelId)
                : fiberPanels.find(p => p.id == panelId);
            
            if (!panel) {
                showToast('Panel bulunamadı', 'error');
                return;
            }
            
            const ports = panelType === 'patch' 
                ? (patchPorts[panelId] || [])
                : (fiberPorts[panelId] || []);
            
            const port = ports.find(p => p.port_number == portNumber);
            
            const modal = document.createElement('div');
            modal.className = 'modal-overlay active';
            modal.id = 'panel-port-edit-modal';
            
            // Mevcut bağlantı bilgilerini al
// Mevcut bağlantı bilgilerini al (geliştirilmiş: switch veya fiber-peer gösterimi)
let currentSwitch = null;
let currentConnectionDetails = null;
let currentPeerFiber = null; // diğer fiber panel bilgisi

if (port) {
    // switch tarafı varsa al
    if (port.connected_switch_id !== undefined && port.connected_switch_id !== null) {
        currentSwitch = switches.find(s => Number(s.id) === Number(port.connected_switch_id)) || null;
    }

    // fiber-peer varsa al (connected_fiber_panel_id / connected_fiber_panel_port)
    if (port.connected_fiber_panel_id) {
        currentPeerFiber = fiberPanels.find(fp => Number(fp.id) === Number(port.connected_fiber_panel_id)) || null;
    }

    // connection_details JSON'u varsa parse et
    if (port.connection_details) {
        try {
            currentConnectionDetails = typeof port.connection_details === 'string'
                ? JSON.parse(port.connection_details)
                : port.connection_details;
        } catch (e) {
            console.warn('panel port connection_details parse hatası', e, port.connection_details);
            currentConnectionDetails = null;
        }
    }
}

// --- HTML preview (Mevcut Bağlantı) - şimdi switch OR fiber_peer veya both gösterir
if (currentConnectionDetails || currentSwitch || currentPeerFiber) {
  // Öncelikle switch bilgisi
  const swName = currentSwitch ? escapeHtml(currentSwitch.name) : (currentConnectionDetails && currentConnectionDetails.switch_name ? escapeHtml(currentConnectionDetails.switch_name) : '');
  const swPort = currentConnectionDetails ? (currentConnectionDetails.switch_port || currentConnectionDetails.port || '') : (port && port.connected_switch_port ? port.connected_switch_port : '');

  // Peer fiber bilgisi
  const peerPanelLetter = currentPeerFiber ? escapeHtml(currentPeerFiber.panel_letter) : '';
  const peerRack = currentPeerFiber ? (racks.find(r => r.id == currentPeerFiber.rack_id)?.name || '') : '';
  const peerPort = port && port.connected_fiber_panel_port ? port.connected_fiber_panel_port : '';

  // Build HTML
  let connectionHtml = `<div style="background: rgba(16, 185, 129, 0.08); border-left: 4px solid #10b981; border-radius: 10px; padding: 12px; margin-bottom: 16px;">
      <div style="color: #10b981; font-weight:700; margin-bottom:8px;"><i class="fas fa-link"></i> Mevcut Bağlantı</div>
      <div style="font-size:0.92rem; color: var(--text);">`;

  if (swName) {
      connectionHtml += `<div><strong>Switch:</strong> ${swName}</div>`;
      connectionHtml += `<div><strong>Port:</strong> ${escapeHtml(swPort || String(portNumber || ''))}</div>`;
  }

  if (peerPanelLetter) {
      connectionHtml += `<div style="margin-top:6px;"><strong>Fiber Peer:</strong> Panel ${peerPanelLetter} ${peerRack ? '• ' + escapeHtml(peerRack) : ''} - Port ${escapeHtml(String(peerPort))}</div>`;
  }

  // Eğer connection_details içinde ek bilgi varsa göster (ör. cihaz/ip/mac)
  if (currentConnectionDetails) {
      if (currentConnectionDetails.device) connectionHtml += `<div><strong>Cihaz:</strong> ${escapeHtml(currentConnectionDetails.device)}</div>`;
      if (currentConnectionDetails.ip) connectionHtml += `<div><strong>IP:</strong> ${escapeHtml(currentConnectionDetails.ip)}</div>`;
      if (currentConnectionDetails.mac) connectionHtml += `<div><strong>MAC:</strong> ${escapeHtml(currentConnectionDetails.mac)}</div>`;
      // Eğer connection_details içinde 'path' veya 'via' gibi köprü bilgileri varsa göster
      if (currentConnectionDetails.path) {
          connectionHtml += `<div style="margin-top:6px;"><strong>Köprü (Path):</strong> ${escapeHtml(currentConnectionDetails.path)}</div>`;
      } else if (currentConnectionDetails.via) {
          connectionHtml += `<div style="margin-top:6px;"><strong>Köprü (Via):</strong> ${escapeHtml(currentConnectionDetails.via)}</div>`;
      }
  }

  connectionHtml += `</div></div>`;

  // Replace placeholder inside modal (mevcut kod yapısıyla uyumlu)
  modal.innerHTML = modal.innerHTML.replace('<!-- MEVCUT_BAGLANTI_PLACEHOLDER -->', connectionHtml);
}
            
            modal.innerHTML = `
                <div class="modal" style="max-width: 600px;">
                    <div class="modal-header">
                        <h3 class="modal-title">
                            ${panelType === 'patch' ? 'Patch' : 'Fiber'} Panel ${panel.panel_letter} - Port ${portNumber}
                        </h3>
                        <button class="modal-close" onclick="closePanelPortEditModal()">&times;</button>
                    </div>
                    
                    <form id="panel-port-edit-form">
                        <input type="hidden" id="edit-panel-id" value="${panelId}">
                        <input type="hidden" id="edit-panel-type" value="${panelType}">
                        <input type="hidden" id="edit-port-number" value="${portNumber}">
                        
                        <!-- Mevcut Bağlantı Bilgisi -->
                        ${currentConnectionDetails ? `
                            <div style="background: rgba(16, 185, 129, 0.1); border-left: 4px solid #10b981; border-radius: 10px; padding: 15px; margin-bottom: 20px;">
                                <h4 style="color: #10b981; margin-bottom: 10px;">
                                    <i class="fas fa-link"></i> Mevcut Bağlantı
                                </h4>
                                <div style="color: var(--text);">
                                    <div><strong>Switch:</strong> ${ currentSwitch ? escapeHtml(currentSwitch.name) : (currentConnectionDetails && currentConnectionDetails.switch_name ? escapeHtml(currentConnectionDetails.switch_name) : 'Bilinmeyen') }</div>
                                    <div><strong>Port:</strong> ${currentConnectionDetails.switch_port}</div>
                                    ${currentConnectionDetails.device ? `<div><strong>Cihaz:</strong> ${currentConnectionDetails.device}</div>` : ''}
                                    ${currentConnectionDetails.ip ? `<div><strong>IP:</strong> ${currentConnectionDetails.ip}</div>` : ''}
                                    ${currentConnectionDetails.mac ? `<div><strong>MAC:</strong> ${currentConnectionDetails.mac}</div>` : ''}
                                </div>
                            </div>
                        ` : ''}
                        
                        <!-- Bağlantı Türü Seçimi -->
                        <div class="form-group">
                            <label class="form-label"><i class="fas fa-plug"></i> Bağlantı Türü</label>
                            <select id="edit-conn-type" class="form-control" onchange="onPanelConnTypeChange()">
                                <option value="switch">Switch</option>
                                <option value="rack_device">Hub SW / Server (Rack Cihazı)</option>
                                <option value="device">Cihaz (Serbest)</option>
                            </select>
                        </div>

                        <!-- Switch Seçimi (default visible) -->
                        <div id="edit-switch-section">
                        <div class="form-group">
                            <label class="form-label">
                                <i class="fas fa-network-wired"></i> Bağlanacak Switch
                            </label>
                            <select id="edit-target-switch" class="form-control">
                                <option value="">Switch Seçin</option>
                            </select>
                            <small style="color: var(--text-light); display: block; margin-top: 5px;">
                                <i class="fas fa-filter"></i> Sadece bu rack'teki switch'ler listelenir
                            </small>
                        </div>
                        
                        <!-- Port Seçimi -->
                        <div class="form-group">
                            <label class="form-label">Switch Port Numarası</label>
                            <select id="edit-target-port" class="form-control" disabled>
                                <option value="">Önce switch seçin</option>
                            </select>
                        </div>
                        </div>

                        <!-- Rack Device Seçimi (hidden by default) -->
                        <div id="edit-rack-device-section" style="display:none;">
                        <div class="form-group">
                            <label class="form-label"><i class="fas fa-sitemap"></i> Bağlanacak Hub SW / Server</label>
                            <select id="edit-target-rack-device" class="form-control" onchange="onRackDeviceChange()">
                                <option value="">Cihaz Seçin</option>
                            </select>
                        </div>
                        <div class="form-group" id="edit-rd-port-row" style="display:none;">
                            <label class="form-label"><i class="fas fa-plug"></i> Port Numarası</label>
                            <select id="edit-target-rd-port" class="form-control">
                                <option value="">Port Seçin</option>
                            </select>
                        </div>
                        </div>

                        <!-- Serbest Cihaz (hidden by default) -->
                        <div id="edit-free-device-section" style="display:none;">
                        <div class="form-group">
                            <label class="form-label"><i class="fas fa-desktop"></i> Cihaz Adı</label>
                            <input type="text" id="edit-free-device-name" class="form-control" placeholder="Örn: PC-MUHASEBE-01" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--dark);color:var(--text);">
                        </div>
                        </div>
                        
                        <!-- Fiber Kuralları Uyarısı -->
                        ${panelType === 'fiber' ? `
                            <div style="background: rgba(239, 68, 68, 0.1); border-left: 4px solid #ef4444; border-radius: 5px; padding: 10px; margin-bottom: 15px;">
                                <small style="color: #ef4444;">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    <strong>Fiber Kuralı:</strong> Bu fiber panel sadece fiber portlara (son 4 port) bağlanabilir
                                </small>
                            </div>
                        ` : ''}
                        
                        <!-- Bağlantı Önizleme -->
                        <div id="edit-connection-preview" style="margin-top: 15px; padding: 15px; background: rgba(15, 23, 42, 0.5); border-radius: 10px; display: none;">
                            <h4 style="color: var(--primary); margin-bottom: 10px;">Bağlantı Önizlemesi</h4>
                            <div id="edit-preview-content"></div>
                        </div>
                        
                        <div style="display: flex; gap: 10px; margin-top: 30px;">
                            ${port && port.connected_switch_id ? `
                                <button type="button" class="btn btn-danger" style="flex: 1;" onclick="disconnectPanelPort()">
                                    <i class="fas fa-unlink"></i> Bağlantıyı Kes
                                </button>
                            ` : ''}
                            <button type="button" class="btn btn-secondary" style="flex: 1;" onclick="closePanelPortEditModal()">
                                İptal
                            </button>
                            <button type="submit" class="btn btn-primary" style="flex: 1;">
                                <i class="fas fa-save"></i> Kaydet
                            </button>
                        </div>
                    </form>
                </div>
            `;
            
            document.body.appendChild(modal);
            
            // Load rack devices into the Hub SW/Server dropdown
            const rackDevSel = document.getElementById('edit-target-rack-device');
            (rackDevices || [])
                .filter(d => d.rack_id == panel.rack_id)
                .forEach(d => {
                    const opt = document.createElement('option');
                    opt.value = d.id;
                    opt.textContent = `${d.name} (${d.device_type === 'hub_sw' ? 'Hub SW' : 'Server'})`;
                    rackDevSel.appendChild(opt);
                });

            // Rack'teki switch'leri yükle
            loadSwitchesForRack(panel.rack_id, panelType, currentSwitch ? currentSwitch.id : null);
            
            // Form submit
            document.getElementById('panel-port-edit-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                await savePanelPortConnection();
            });
        }

        // Toggle visibility of connection type sections
        function onPanelConnTypeChange() {
            const t = document.getElementById('edit-conn-type').value;
            document.getElementById('edit-switch-section').style.display      = (t === 'switch')      ? '' : 'none';
            document.getElementById('edit-rack-device-section').style.display = (t === 'rack_device') ? '' : 'none';
            document.getElementById('edit-free-device-section').style.display = (t === 'device')      ? '' : 'none';
            // Reset port dropdown when switching away
            if (t !== 'rack_device') {
                document.getElementById('edit-rd-port-row').style.display = 'none';
            }
        }

        // When a rack device is selected, populate its port dropdown
        function onRackDeviceChange() {
            const rdId = document.getElementById('edit-target-rack-device').value;
            const portRow = document.getElementById('edit-rd-port-row');
            const portSel = document.getElementById('edit-target-rd-port');
            portSel.innerHTML = '<option value="">Port Seçin</option>';
            if (!rdId) { portRow.style.display = 'none'; return; }
            const rd = (rackDevices || []).find(d => d.id == rdId);
            if (!rd || (rd.ports <= 0 && rd.fiber_ports <= 0)) { portRow.style.display = 'none'; return; }
            const total = Math.min((rd.ports || 0) + (rd.fiber_ports || 0), 512);
            for (let p = 1; p <= total; p++) {
                portSel.innerHTML += `<option value="${p}">${p}</option>`;
            }
            portRow.style.display = '';
        }

        // Rack'teki switch'leri listele
        function loadSwitchesForRack(rackId, panelType, selectedSwitchId = null) {
            const switchSelect = document.getElementById('edit-target-switch');
            const portSelect = document.getElementById('edit-target-port');
            
            // Bu rack'teki switch'leri filtrele
            const rackSwitches = switches.filter(s => s.rack_id == rackId);
            
            if (rackSwitches.length === 0) {
                switchSelect.innerHTML = '<option value="">Bu rack\'te switch yok</option>';
                return;
            }
            
            switchSelect.innerHTML = '<option value="">Switch Seçin</option>';
            rackSwitches.forEach(sw => {
                const option = document.createElement('option');
                option.value = sw.id;
                option.textContent = `${sw.name} (${sw.ports} port)`;
                option.dataset.ports = sw.ports;
                option.dataset.fiberStart = sw.ports - 3; // Fiber portlar son 4 port
                if (sw.id == selectedSwitchId) {
                    option.selected = true;
                }
                switchSelect.appendChild(option);
            });
            
            // Switch değiştiğinde portları yükle
            switchSelect.addEventListener('change', function() {
                loadPortsForSwitch(this.value, panelType);
            });
            
            // Eğer switch seçiliyse portları yükle
            if (selectedSwitchId) {
                loadPortsForSwitch(selectedSwitchId, panelType);
            }
        }

        // Switch portlarını listele
        function loadPortsForSwitch(switchId, panelType) {
            const portSelect = document.getElementById('edit-target-port');
            const previewDiv = document.getElementById('edit-connection-preview');
            
            if (!switchId) {
                portSelect.innerHTML = '<option value="">Önce switch seçin</option>';
                portSelect.disabled = true;
                previewDiv.style.display = 'none';
                return;
            }
            
            const sw = switches.find(s => s.id == switchId);
            if (!sw) return;
            
            const fiberStartPort = sw.ports - 3;
            const switchPorts = portConnections[switchId] || [];
            
            portSelect.innerHTML = '<option value="">Port Seçin</option>';
            
            for (let i = 1; i <= sw.ports; i++) {
                const isFiberPort = i >= fiberStartPort;
                const port = switchPorts.find(p => p.port === i);
                
                // Fiber panel ise sadece fiber portları göster
                if (panelType === 'fiber' && !isFiberPort) continue;
                
                // Patch panel ise fiber portları gösterme
                if (panelType === 'patch' && isFiberPort) continue;
                
                const option = document.createElement('option');
                option.value = i;
                
                let portText = `Port ${i} (${isFiberPort ? 'Fiber' : 'Ethernet'})`;
                
                // Port dolu mu kontrol et
                if (port && port.is_active) {
                    portText += ` - DOLU: ${port.device || 'Bilinmeyen'}`;
                    option.style.color = '#f59e0b';
                } else {
                    portText += ' - BOŞ';
                }
                
                option.textContent = portText;
                option.dataset.portInfo = port ? JSON.stringify(port) : '';
                
                portSelect.appendChild(option);
            }
            
            portSelect.disabled = false;
            
            // Port seçimi değiştiğinde önizleme göster
            portSelect.addEventListener('change', function() {
                updateConnectionPreview();
            });
        }

        // Bağlantı önizlemesi
        function updateConnectionPreview() {
            const switchId = document.getElementById('edit-target-switch').value;
            const portNo = document.getElementById('edit-target-port').value;
            const previewDiv = document.getElementById('edit-connection-preview');
            const previewContent = document.getElementById('edit-preview-content');
            
            if (!switchId || !portNo) {
                previewDiv.style.display = 'none';
                return;
            }
            
            const sw = switches.find(s => s.id == switchId);
            const switchPorts = portConnections[switchId] || [];
            const port = switchPorts.find(p => p.port == portNo);
            
            let html = `
                <div style="font-size: 0.9rem;">
                    <div><strong>Switch:</strong> ${sw.name}</div>
                    <div><strong>Port:</strong> ${portNo}</div>
            `;
            
            if (port && port.is_active) {
                html += `
                    <div><strong>Mevcut Cihaz:</strong> ${port.device || 'Yok'}</div>
                    ${port.ip ? `<div><strong>IP:</strong> ${port.ip}</div>` : ''}
                    ${port.mac ? `<div><strong>MAC:</strong> ${port.mac}</div>` : ''}
                    ${port.connection_info_preserved ? (() => {
                        try {
                            const cp = JSON.parse(port.connection_info_preserved);
                            if (cp && cp.type === 'virtual_core') {
                                const nm = unwrapCoreSwitchName(cp.core_switch_name || '');
                                return `<div style="margin-top:10px;padding:10px;background:rgba(245,158,11,0.1);border-radius:5px;">
                                    <strong style="color:#fbbf24;">Core Switch Bağlantısı:</strong><br>
                                    <small>${escapeHtml(nm)} ${cp.core_port_label ? '| ' + escapeHtml(cp.core_port_label) : ''}</small>
                                </div>`;
                            } else if (cp && cp.type === 'virtual_core_reverse') {
                                return `<div style="margin-top:10px;padding:10px;background:rgba(52,211,153,0.1);border-radius:5px;">
                                    <strong style="color:#34d399;">Edge Switch Bağlantısı:</strong><br>
                                    <small>${escapeHtml(cp.edge_switch_name || '')} port ${cp.edge_port_no || ''}</small>
                                </div>`;
                            }
                        } catch(e) {}
                        // Fallback: plain text (not JSON)
                        return `<div style="margin-top:10px;padding:10px;background:rgba(59,130,246,0.1);border-radius:5px;">
                            <strong>Connection Bilgisi:</strong><br>
                            <small>${escapeHtml(port.connection_info_preserved)}</small>
                        </div>`;
                    })() : ''}
                `;
            } else {
                html += `<div style="color: #10b981;"><i class="fas fa-check-circle"></i> Port boş, bağlantı kurulabilir</div>`;
            }
            
            html += '</div>';
            
            previewContent.innerHTML = html;
            previewDiv.style.display = 'block';
        }


// ADD: new function editFiberPort(panelId, portNumber)
// Place near other modal helper functions

function editFiberPort(panelId, portNumber) {
  // Minimal, client-side modal to set side_a / side_b
  // (Full function as provided earlier in conversation)
  // For brevity include full function here:
  // ----- START -----
  const modal = document.createElement('div');
  modal.className = 'modal-overlay active';
  modal.innerHTML = `
    <div class="modal" style="max-width:600px;">
      <div class="modal-header">
        <h3 class="modal-title">Fiber Panel ${panelId} - Port ${portNumber}</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div style="padding:15px;">
        <div style="margin-bottom:12px;">
          <label class="form-label">Side A</label>
          <select id="fp-side-a-type" class="form-control">
            <option value="">Seçim</option>
            <option value="none">Boş</option>
            <option value="switch">Switch'e Bağla</option>
            <option value="fiber_port">Başka Fiber Port'a Bağla</option>
          </select>
          <div id="fp-side-a-controls" style="margin-top:8px;"></div>
        </div>

        <div style="margin-bottom:12px;">
          <label class="form-label">Side B</label>
          <select id="fp-side-b-type" class="form-control">
            <option value="">Seçim</option>
            <option value="none">Boş</option>
            <option value="switch">Switch'e Bağla</option>
            <option value="fiber_port">Başka Fiber Port'a Bağla</option>
          </select>
          <div id="fp-side-b-controls" style="margin-top:8px;"></div>
        </div>

        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:12px;">
          <button class="btn btn-secondary" id="fp-cancel-btn">İptal</button>
          <button class="btn btn-primary" id="fp-save-btn">Kaydet</button>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  modal.querySelector('.modal-close').addEventListener('click', () => modal.remove());
  modal.querySelector('#fp-cancel-btn').addEventListener('click', () => modal.remove());

// REPLACE or add inside editFiberPort scope: makeSwitchSelect now accepts optional rackId

// --- REPLACE or ADD: improved makeSwitchSelect + editFiberPort + small preview helpers ---

/**
 * makeSwitchSelect(selectId, rackId)
 * - selectId: id to assign to the created <select>
 * - rackId (optional): when provided, only show switches with that rack_id
 */
function makeSwitchSelect(selectId, rackId = null) {
  const sel = document.createElement('select');
  sel.className = 'form-control';
  sel.id = selectId;
  sel.innerHTML = `<option value="">Switch Seç</option>`;

  // filter by rack if provided; always include core switches regardless of rack
  let list = switches || [];
  let coreSwitches = list.filter(s => s.is_core == 1 || s.is_core === true || s.is_core === '1');
  if (rackId !== null && rackId !== undefined) {
    list = list.filter(s => Number(s.rack_id) === Number(rackId));
    // Add core switches that are not already in list
    coreSwitches.forEach(cs => { if (!list.find(s => s.id === cs.id)) list.push(cs); });
  }

  list.forEach(sw => {
    const isCoreItem = sw.is_core == 1 || sw.is_core === true || sw.is_core === '1';
    const opt = document.createElement('option');
    opt.value = sw.id;
    opt.textContent = `${isCoreItem ? '⭐ ' : ''}${sw.name} (${sw.ports} port)`;
    opt.dataset.ports = sw.ports;
    opt.dataset.fiberStart = isCoreItem ? 1 : Math.max(1, sw.ports - 3); // core: all ports fiber
    opt.dataset.isCore = isCoreItem ? '1' : '0';
    sel.appendChild(opt);
  });

  // If after filtering no switches, show friendly message
  if (list.length === 0) {
    sel.innerHTML = `<option value="">Bu rack'te switch yok</option>`;
    sel.disabled = true;
  }

  return sel;
}

/**
 * editFiberPort(panelId, portNumber, rackId)
 * - rackId: pass panel.rack_id so switch lists are limited to the same rack
 */
function editFiberPort(panelId, portNumber, rackId = null) {
  // Minimal, client-side modal to set side_a / side_b with rack-scoped switch selects
  const modal = document.createElement('div');
  modal.className = 'modal-overlay active';
  modal.innerHTML = `
    <div class="modal" style="max-width:600px;">
      <div class="modal-header">
        <h3 class="modal-title">Fiber Panel ${panelId} - Port ${portNumber}</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div style="padding:15px;">
        <div style="margin-bottom:12px;">
          <label class="form-label">Side A</label>
          <select id="fp-side-a-type" class="form-control">
            <option value="">Seçim</option>
            <option value="none">Boş</option>
            <option value="switch">Switch'e Bağla</option>
            <option value="fiber_port">Başka Fiber Port'a Bağla</option>
          </select>
          <div id="fp-side-a-controls" style="margin-top:8px;"></div>
        </div>

        <div style="margin-bottom:12px;">
          <label class="form-label">Side B</label>
          <select id="fp-side-b-type" class="form-control">
            <option value="">Seçim</option>
            <option value="none">Boş</option>
            <option value="switch">Switch'e Bağla</option>
            <option value="fiber_port">Başka Fiber Port'a Bağla</option>
          </select>
          <div id="fp-side-b-controls" style="margin-top:8px;"></div>
        </div>

        <div id="fp-bridge-preview" style="margin-top:12px; padding:12px; background: rgba(15,23,42,0.5); border-radius:8px; display:none;">
          <strong style="color: var(--primary);">Bağlantı Önizlemesi:</strong>
          <div id="fp-bridge-text" style="margin-top:8px; color: var(--text);"></div>
        </div>

        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:12px;">
          <button class="btn btn-secondary" id="fp-cancel-btn">İptal</button>
          <button class="btn btn-primary" id="fp-save-btn">Kaydet</button>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  // close handlers
  modal.querySelector('.modal-close').addEventListener('click', () => modal.remove());
  modal.querySelector('#fp-cancel-btn').addEventListener('click', () => modal.remove());

  // helpers to create controls
  function makeFiberPanelPortSelect(selectId) {
    const container = document.createElement('div');
    container.style.display = 'grid';
    container.style.gridTemplateColumns = '1fr 1fr';
    container.style.gap = '8px';
    const panelSel = document.createElement('select');
    panelSel.className = 'form-control';
    panelSel.id = selectId + '_panel';
    panelSel.innerHTML = `<option value="">Panel Seç</option>`;
    fiberPanels.forEach(fp => {
      const opt = document.createElement('option');
      opt.value = fp.id;
      opt.textContent = `${fp.panel_letter} • ${fp.total_fibers}f • ${racks.find(r=>r.id==fp.rack_id)?.name || ''}`;
      opt.dataset.max = fp.total_fibers;
      container.appendChild(opt); // NOTE: we will append properly below
      panelSel.appendChild(opt);
    });
    const portSel = document.createElement('select');
    portSel.className = 'form-control';
    portSel.id = selectId + '_port';
    portSel.innerHTML = '<option value="">Önce panel seçin</option>';
    panelSel.addEventListener('change', function() {
      const max = Number(this.options[this.selectedIndex].dataset.max || 0);
      portSel.innerHTML = '<option value="">Port Seç</option>';
      for (let i=1;i<=max;i++) {
        const o = document.createElement('option'); o.value = i; o.textContent = `Port ${i}`;
        portSel.appendChild(o);
      }
      updateBridgePreview();
    });
    container.appendChild(panelSel);
    container.appendChild(portSel);
    return container;
  }

  // attach dynamic controls based on type selection
  const sideAType = modal.querySelector('#fp-side-a-type');
  const sideAControls = modal.querySelector('#fp-side-a-controls');
  sideAType.addEventListener('change', function() {
    sideAControls.innerHTML = '';
    if (this.value === 'switch') {
      // create rack-scoped switch select
      const sel = makeSwitchSelect('fp-side-a-switch', rackId);
      sideAControls.appendChild(sel);
      const portSel = document.createElement('select');
      portSel.className = 'form-control';
      portSel.id = 'fp-side-a-switch-port';
      portSel.innerHTML = '<option value="">Önce switch seçin</option>';
      sideAControls.appendChild(portSel);
      sel.addEventListener('change', function() {
        portSel.innerHTML = '<option value="">Port Seç</option>';
        const swId = Number(this.value);
        const sw = switches.find(s => Number(s.id) === swId);
        if (sw) {
          const isCoreOpt = sw.is_core == 1 || sw.is_core === true || sw.is_core === '1';
          const fiberStart = isCoreOpt ? 1 : Math.max(1, sw.ports - 3);
          const csPorts = portConnections[swId] || [];
          for (let p = fiberStart; p <= sw.ports; p++) {
            const cpConn = csPorts.find(x => x.port === p);
            const lbl = (isCoreOpt && cpConn && cpConn.port_label) ? cpConn.port_label : `Port ${p}${isCoreOpt ? '' : ' (Fiber)'}`;
            const o = document.createElement('option'); o.value = p; o.textContent = lbl;
            portSel.appendChild(o);
          }
        }
        updateBridgePreview();
      });
      portSel.addEventListener('change', updateBridgePreview);
    } else if (this.value === 'fiber_port') {
      const fsel = makeFiberPanelPortSelect('fp-side-a-fpanel');
      sideAControls.appendChild(fsel);
      fsel.querySelector('select')?.addEventListener('change', updateBridgePreview);
      fsel.querySelector('select[id$="_port"]')?.addEventListener('change', updateBridgePreview);
    } else {
      updateBridgePreview();
    }
  });

  const sideBType = modal.querySelector('#fp-side-b-type');
  const sideBControls = modal.querySelector('#fp-side-b-controls');
  sideBType.addEventListener('change', function() {
    sideBControls.innerHTML = '';
    if (this.value === 'switch') {
      const sel = makeSwitchSelect('fp-side-b-switch', rackId);
      sideBControls.appendChild(sel);
      const portSel = document.createElement('select');
      portSel.className = 'form-control';
      portSel.id = 'fp-side-b-switch-port';
      portSel.innerHTML = '<option value="">Önce switch seçin</option>';
      sideBControls.appendChild(portSel);
      sel.addEventListener('change', function() {
        portSel.innerHTML = '<option value="">Port Seç</option>';
        const swId = Number(this.value);
        const sw = switches.find(s => Number(s.id) === swId);
        if (sw) {
          const isCoreOpt = sw.is_core == 1 || sw.is_core === true || sw.is_core === '1';
          const fiberStart = isCoreOpt ? 1 : Math.max(1, sw.ports - 3);
          const csPorts = portConnections[swId] || [];
          for (let p = fiberStart; p <= sw.ports; p++) {
            const cpConn = csPorts.find(x => x.port === p);
            const lbl = (isCoreOpt && cpConn && cpConn.port_label) ? cpConn.port_label : `Port ${p}${isCoreOpt ? '' : ' (Fiber)'}`;
            const o = document.createElement('option'); o.value = p; o.textContent = lbl;
            portSel.appendChild(o);
          }
        }
        updateBridgePreview();
      });
      portSel.addEventListener('change', updateBridgePreview);
    } else if (this.value === 'fiber_port') {
      const fsel = makeFiberPanelPortSelect('fp-side-b-fpanel');
      sideBControls.appendChild(fsel);
      fsel.querySelector('select')?.addEventListener('change', updateBridgePreview);
      fsel.querySelector('select[id$="_port"]')?.addEventListener('change', updateBridgePreview);
    } else {
      updateBridgePreview();
    }
  });

  // prefill if existing connection data present (try to read fiberPorts data)
  const existing = (fiberPorts[panelId] || []).find(p => Number(p.port_number) === Number(portNumber));
  if (existing) {
    // If connected to switch
    if (existing.connected_switch_id) {
      sideAType.value = 'switch';
      sideAType.dispatchEvent(new Event('change'));
      setTimeout(()=> {
        const s = modal.querySelector('#fp-side-a-switch');
        const psel = modal.querySelector('#fp-side-a-switch-port');
        if (s) s.value = existing.connected_switch_id;
        if (psel) psel.value = existing.connected_switch_port;
        updateBridgePreview();
      }, 80);
    } else if (existing.connected_fiber_panel_id) {
      sideAType.value = 'fiber_port';
      sideAType.dispatchEvent(new Event('change'));
      // user may need to pick exact panel/port when panel list loads
      setTimeout(()=> {
        const panelSel = modal.querySelector('#fp-side-a-fpanel_panel');
        const portSel = modal.querySelector('#fp-side-a-fpanel_port');
        if (panelSel) panelSel.value = existing.connected_fiber_panel_id;
        if (portSel) portSel.value = existing.connected_fiber_panel_port;
        updateBridgePreview();
      }, 120);
    }
  }

  // Bridge preview logic
  function updateBridgePreview() {
    const previewWrap = modal.querySelector('#fp-bridge-preview');
    const bridgeText = modal.querySelector('#fp-bridge-text');

    // read side A selection
    const aType = modal.querySelector('#fp-side-a-type').value;
    let aDesc = 'Boş';
    if (aType === 'switch') {
      const sId = modal.querySelector('#fp-side-a-switch')?.value;
      const p = modal.querySelector('#fp-side-a-switch-port')?.value;
      const sw = switches.find(s => String(s.id) === String(sId));
      aDesc = sw ? `${sw.name} : Port ${p || '?'}` : (sId ? `SW#${sId} : Port ${p||'?'}` : 'Seçili değil');
    } else if (aType === 'fiber_port') {
      const panel = modal.querySelector('#fp-side-a-fpanel_panel')?.value;
      const port = modal.querySelector('#fp-side-a-fpanel_port')?.value;
      aDesc = panel ? `Panel ${modal.querySelector('#fp-side-a-fpanel_panel').selectedOptions[0].text.split(' ')[0]} : Port ${port||'?'}` : 'Seçili değil';
    }

    // side B
    const bType = modal.querySelector('#fp-side-b-type').value;
    let bDesc = 'Boş';
    if (bType === 'switch') {
      const sId = modal.querySelector('#fp-side-b-switch')?.value;
      const p = modal.querySelector('#fp-side-b-switch-port')?.value;
      const sw = switches.find(s => String(s.id) === String(sId));
      bDesc = sw ? `${sw.name} : Port ${p || '?'}` : (sId ? `SW#${sId} : Port ${p||'?'}` : 'Seçili değil');
    } else if (bType === 'fiber_port') {
      const panel = modal.querySelector('#fp-side-b-fpanel_panel')?.value;
      const port = modal.querySelector('#fp-side-b-fpanel_port')?.value;
      bDesc = panel ? `Panel ${modal.querySelector('#fp-side-b-fpanel_panel').selectedOptions[0].text.split(' ')[0]} : Port ${port||'?'}` : 'Seçili değil';
    }

    // show preview if at least one side has something
    if ((aType && aType !== 'none') || (bType && bType !== 'none')) {
      previewWrap.style.display = 'block';
      bridgeText.innerHTML = `<div style="display:flex;gap:10px;align-items:center;">
                                <div style="flex:1;color:var(--text-light)"><strong>Side A:</strong> ${escapeHtml(aDesc)}</div>
                                <div style="font-size:1.1rem;color:var(--primary)">➜</div>
                                <div style="flex:1;color:var(--text-light)"><strong>Side B:</strong> ${escapeHtml(bDesc)}</div>
                              </div>`;
    } else {
      previewWrap.style.display = 'none';
      bridgeText.innerHTML = '';
    }
  }

  // save handler - build payload and POST to API
  modal.querySelector('#fp-save-btn').addEventListener('click', async function() {
    const payload = { panelId: panelId, panelPort: portNumber, side_a: null, side_b: null };

    // collect side A
    const aType = sideAType.value;
    if (aType === 'switch') {
      const sid = modal.querySelector('#fp-side-a-switch')?.value;
      const sport = modal.querySelector('#fp-side-a-switch-port')?.value;
      if (sid && sport) payload.side_a = { type:'switch', id: Number(sid), port: Number(sport) };
    } else if (aType === 'fiber_port') {
      const pid = modal.querySelector('#fp-side-a-fpanel_panel')?.value;
      const pport = modal.querySelector('#fp-side-a-fpanel_port')?.value;
      if (pid && pport) payload.side_a = { type:'fiber_port', panel_id: Number(pid), port: Number(pport) };
    }

    // collect side B
    const bType = sideBType.value;
    if (bType === 'switch') {
      const sid = modal.querySelector('#fp-side-b-switch')?.value;
      const sport = modal.querySelector('#fp-side-b-switch-port')?.value;
      if (sid && sport) payload.side_b = { type:'switch', id: Number(sid), port: Number(sport) };
    } else if (bType === 'fiber_port') {
      const pid = modal.querySelector('#fp-side-b-fpanel_panel')?.value;
      const pport = modal.querySelector('#fp-side-b-fpanel_port')?.value;
      if (pid && pport) payload.side_b = { type:'fiber_port', panel_id: Number(pid), port: Number(pport) };
    }

    if (!payload.side_a && !payload.side_b) {
      showToast('En az bir tarafı bağlamalısınız', 'warning');
      return;
    }

    try {
      showLoading();
      const resp = await fetch('actions/saveFiberPortConnection.php', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const res = await resp.json();
      if (res.success) {
        showToast('Fiber port bağlantısı kaydedildi','success');
        modal.remove();
        await loadData();
      } else {
        throw new Error(res.message || 'Kayıt başarısız');
      }
    } catch(err){
      console.error(err);
      showToast('Kaydetme hatası: '+err.message,'error');
    } finally {
      hideLoading();
    }
  });
  

  // we must update preview when any control changes
  setTimeout(()=> {
    modal.querySelectorAll('select').forEach(s => s.addEventListener('change', updateBridgePreview));
    updateBridgePreview();
  }, 100);
}
}

        // Panel port bağlantısını kaydet
        async function savePanelPortConnection() {
            const panelId = document.getElementById('edit-panel-id').value;
            const panelType = document.getElementById('edit-panel-type').value;
            const portNumber = document.getElementById('edit-port-number').value;
            const connType = document.getElementById('edit-conn-type')?.value || 'switch';

            // ── Rack Device (Hub SW / Server) bağlantısı ───────────────
            if (connType === 'rack_device') {
                const rdId = document.getElementById('edit-target-rack-device').value;
                if (!rdId) { showToast('Lütfen bir cihaz seçin', 'warning'); return; }
                const rd = (rackDevices || []).find(d => d.id == rdId);
                if (!rd) { showToast('Cihaz bulunamadı', 'error'); return; }
                const rdPortRaw = document.getElementById('edit-target-rd-port')?.value || '';
                const rdPortNum = rdPortRaw !== '' ? parseInt(rdPortRaw, 10) : null;
                try {
                    showLoading();
                    const response = await fetch('actions/savePatchPanel.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            action: 'save_port_connection',
                            panelId: parseInt(panelId),
                            panelType: panelType,
                            portNumber: parseInt(portNumber),
                            connType: 'rack_device',
                            rackDeviceId: parseInt(rdId),
                            rackDeviceName: rd.name,
                            rackDevicePort: (rdPortNum !== null && !isNaN(rdPortNum)) ? rdPortNum : null
                        })
                    });
                    const result = await response.json();
                    if (result.success) {
                        const portLabel = (rdPortNum && !isNaN(rdPortNum)) ? ` Port ${rdPortNum}` : '';
                        showToast(`${rd.name}${portLabel} bağlantısı kaydedildi`, 'success');
                        closePanelPortEditModal();
                        await loadData();
                        window.showPanelDetail(panelId, panelType);
                    } else {
                        throw new Error(result.error || 'Kayıt başarısız');
                    }
                } catch (error) {
                    showToast('Bağlantı kaydedilemedi: ' + error.message, 'error');
                } finally {
                    hideLoading();
                }
                return;
            }

            // ── Serbest Cihaz bağlantısı ────────────────────────────────
            if (connType === 'device') {
                const deviceName = (document.getElementById('edit-free-device-name').value || '').trim();
                if (!deviceName) { showToast('Lütfen cihaz adını girin', 'warning'); return; }
                try {
                    showLoading();
                    const response = await fetch('actions/savePatchPanel.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            action: 'save_port_connection',
                            panelId: parseInt(panelId),
                            panelType: panelType,
                            portNumber: parseInt(portNumber),
                            connType: 'device',
                            deviceName: deviceName
                        })
                    });
                    const result = await response.json();
                    if (result.success) {
                        showToast(`${deviceName} bağlantısı kaydedildi`, 'success');
                        closePanelPortEditModal();
                        await loadData();
                        window.showPanelDetail(panelId, panelType);
                    } else {
                        throw new Error(result.error || 'Kayıt başarısız');
                    }
                } catch (error) {
                    showToast('Bağlantı kaydedilemedi: ' + error.message, 'error');
                } finally {
                    hideLoading();
                }
                return;
            }

            // ── Switch bağlantısı (mevcut davranış) ─────────────────────
            const targetSwitchId = document.getElementById('edit-target-switch').value;
            const targetPort = document.getElementById('edit-target-port').value;
            
            if (!targetSwitchId || !targetPort) {
                showToast('Lütfen switch ve port seçin', 'warning');
                return;
            }
            
            try {
                showLoading();
                
                const response = await fetch('actions/savePanelToSwitchConnection.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        panelId: parseInt(panelId),
                        panelType: panelType,
                        panelPort: parseInt(portNumber),
                        switchId: parseInt(targetSwitchId),
                        switchPort: parseInt(targetPort)
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showToast('Panel bağlantısı kaydedildi ve switch senkronize edildi', 'success');
                    closePanelPortEditModal();
                    await loadData();
                    
                    // Panel detayını yenile
                    window.showPanelDetail(panelId, panelType);
                } else {
                    throw new Error(result.error || 'Kayıt başarısız');
                }
            } catch (error) {
                console.error('Panel bağlantı hatası:', error);
                showToast('Bağlantı kaydedilemedi: ' + error.message, 'error');
            } finally {
                hideLoading();
            }
        }

        // Panel port bağlantısını kes
        async function disconnectPanelPort() {
            if (!confirm('Bu panel portundaki bağlantıyı kesmek istediğinize emin misiniz? Switch portu da boşa çekilecek.')) {
                return;
            }
            
            const panelId = document.getElementById('edit-panel-id').value;
            const panelType = document.getElementById('edit-panel-type').value;
            const portNumber = document.getElementById('edit-port-number').value;
            
            try {
                showLoading();
                
                const response = await fetch('actions/disconnectPanelPort.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        panelId: parseInt(panelId),
                        panelType: panelType,
                        portNumber: parseInt(portNumber)
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showToast('Bağlantı kesildi ve switch portu boşa çekildi', 'success');
                    closePanelPortEditModal();
                    await loadData();
                    window.showPanelDetail(panelId, panelType);
                } else {
                    throw new Error(result.error || 'Bağlantı kesilemedi');
                }
            } catch (error) {
                console.error('Bağlantı kesme hatası:', error);
                showToast('Bağlantı kesilemedi: ' + error.message, 'error');
            } finally {
                hideLoading();
            }
        }

        // Modal'ı kapat
        function closePanelPortEditModal() {
            const modal = document.getElementById('panel-port-edit-modal');
            if (modal) {
                modal.remove();
            }
        }

        /* ─── Hub SW Port Modal ─────────────────────────────── */
        function openHubSwPortModal(rdId) {
            const rd = (rackDevices || []).find(d => d.id == rdId);
            if (!rd) return;

            const isHub = rd.device_type === 'hub_sw';
            const devColor  = isHub ? '#fbbf24' : '#c4b5fd';
            const devBorder = isHub ? '#d97706' : '#7c3aed';
            const devIcon   = isHub ? 'fa-sitemap' : 'fa-server';
            const devLabel  = isHub ? 'Hub SW' : 'Server';

            // Build reverse lookup: hub SW port → connected patch panel port(s)
            const portToPatch = {}; // portNum → [{panelId, panelLetter, portNumber}]
            Object.entries(patchPorts).forEach(([panelId, pts]) => {
                (pts || []).forEach(pp => {
                    if (!pp.connection_details) return;
                    try {
                        const cd = typeof pp.connection_details === 'string' ? JSON.parse(pp.connection_details) : pp.connection_details;
                        if (cd && parseInt(cd.rack_device_id) === parseInt(rdId) && cd.rack_device_port) {
                            const pNum = parseInt(cd.rack_device_port);
                            const panel = patchPanels.find(p => p.id == panelId);
                            if (!portToPatch[pNum]) portToPatch[pNum] = [];
                            portToPatch[pNum].push({panelId: parseInt(panelId), panelLetter: panel ? panel.panel_letter : '?', portNumber: parseInt(pp.port_number)});
                        }
                    } catch(e) {}
                });
            });

            // Also check hubSwPortConnections for direct device connections
            const directConns = {};
            (hubSwPortConnections || []).filter(c => c.rack_device_id == rdId).forEach(c => {
                directConns[parseInt(c.port_number)] = c;
            });

            const totalPorts = (rd.ports || 0) + (rd.fiber_ports || 0);
            const connCount  = Object.keys(portToPatch).length + Object.keys(directConns).length;
            const rack = racks.find(r => r.id == rd.rack_id);

            let portGrid = '';
            for (let i = 1; i <= totalPorts; i++) {
                const patchConn  = portToPatch[i];
                const directConn = directConns[i];
                const isConn     = (patchConn && patchConn.length > 0) || !!directConn;
                const bg     = isConn ? '#064e3b' : '#1e293b';
                const border = isConn ? '#10b981' : '#334155';
                let subLabel = '';
                if (patchConn && patchConn.length > 0) {
                    subLabel = patchConn.map(c => `P.${c.panelLetter}:${c.portNumber}`).join(', ');
                } else if (directConn && directConn.device_name) {
                    subLabel = directConn.device_name.substring(0, 10);
                }
                const isFiber = i > (rd.ports || 0);
                const portBg  = isFiber ? (isConn ? '#064e3b' : '#0c1a20') : bg;
                portGrid += `<div onclick="openHubSwPortEditModal(${rdId},${i})"
                    style="background:${portBg};border:1px solid ${border};border-radius:8px;padding:10px 4px;text-align:center;cursor:pointer;transition:all 0.15s;"
                    onmouseover="this.style.opacity='0.75'" onmouseout="this.style.opacity='1'">
                    <div style="font-size:0.85rem;font-weight:700;color:${isConn ? '#10b981' : '#94a3b8'};">${i}${isFiber ? '<span style="font-size:0.6rem;color:#0891b2;display:block;">F</span>' : ''}</div>
                    ${subLabel ? `<div style="font-size:0.6rem;color:#64748b;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:58px;">${escapeHtml(subLabel)}</div>` : ''}
                    ${isConn ? '<div style="width:6px;height:6px;background:#10b981;border-radius:50%;margin:4px auto 0;"></div>' : ''}
                </div>`;
            }

            // Use the static rd-device-modal element (avoids z-index conflict with rack-detail-modal)
            const header  = document.getElementById('rd-device-modal-header');
            const title   = document.getElementById('rd-device-modal-title');
            const content = document.getElementById('rd-device-modal-content');
            const overlay = document.getElementById('rd-device-modal');

            // Style header to match device type
            header.style.background    = isHub ? 'linear-gradient(135deg,#1a1400,#2d1f00)' : 'linear-gradient(135deg,#120d1a,#1e1030)';
            header.style.borderBottom  = `2px solid ${devBorder}`;
            title.style.color          = devColor;
            title.innerHTML            = `<i class="fas ${devIcon}" style="margin-right:8px;"></i>${escapeHtml(rd.name)} <span style="font-size:0.8rem;opacity:0.7;font-weight:400;">${devLabel} · ${totalPorts}P</span>`;

            content.innerHTML = `
                <div style="padding:20px;">
                    <div style="color:var(--text-light);margin-bottom:16px;">
                        <i class="fas fa-server" style="margin-right:4px;"></i>
                        ${rack ? escapeHtml(rack.name) : ''}
                        ${rd.position_in_rack ? ` &bull; Slot ${rd.position_in_rack}` : ''}
                    </div>
                    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;">
                        <span style="background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.3);border-radius:20px;padding:4px 12px;font-size:0.85rem;">
                            <i class="fas fa-link"></i> ${connCount} Bağlı Port
                        </span>
                        <span style="background:rgba(100,116,139,0.15);color:#94a3b8;border:1px solid rgba(100,116,139,0.3);border-radius:20px;padding:4px 12px;font-size:0.85rem;">
                            <i class="fas fa-plug"></i> ${totalPorts} Toplam Port
                        </span>
                    </div>
                    <div style="color:#64748b;font-size:0.82rem;margin-bottom:14px;"><i class="fas fa-hand-pointer"></i> Bir porta tıkla → bağlantı ekle / düzenle</div>
                    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(62px,1fr));gap:6px;">
                        ${totalPorts > 0 ? portGrid : '<p style="color:#64748b;">Bu cihazda port tanımlı değil.</p>'}
                    </div>
                </div>
            `;

            // Close rack-detail-modal so there's no layering issue
            document.getElementById('rack-detail-modal').classList.remove('active');
            overlay.classList.add('active');
        }

        function closeHubSwPortModal() {
            const m = document.getElementById('rd-device-modal');
            if (m) m.classList.remove('active');
        }

        function openHubSwPortEditModal(rdId, portNum) {
            const rd = (rackDevices || []).find(d => d.id == rdId);
            if (!rd) return;

            // Find connected patch panel ports
            const patchConns = [];
            Object.entries(patchPorts).forEach(([panelId, pts]) => {
                (pts || []).forEach(pp => {
                    if (!pp.connection_details) return;
                    try {
                        const cd = typeof pp.connection_details === 'string' ? JSON.parse(pp.connection_details) : pp.connection_details;
                        if (cd && parseInt(cd.rack_device_id) === parseInt(rdId) && parseInt(cd.rack_device_port) === portNum) {
                            const panel = patchPanels.find(p => p.id == panelId);
                            patchConns.push({panelId: parseInt(panelId), panelLetter: panel ? panel.panel_letter : '?', portNumber: parseInt(pp.port_number), panel});
                        }
                    } catch(e) {}
                });
            });

            // Find direct device connection
            const directConn = (hubSwPortConnections || []).find(c => c.rack_device_id == rdId && parseInt(c.port_number) === portNum) || null;

            // Build "existing connections" display
            let existingHtml = '';
            if (patchConns.length > 0) {
                existingHtml += `<div style="background:rgba(16,185,129,0.08);border-left:4px solid #10b981;border-radius:8px;padding:12px;margin-bottom:12px;">
                    <div style="color:#10b981;font-weight:700;margin-bottom:6px;"><i class="fas fa-link"></i> Mevcut Bağlantı</div>`;
                patchConns.forEach(c => {
                    // Check if that patch panel port also connects to a switch
                    const pts = patchPorts[c.panelId] || [];
                    const pp = pts.find(p => p.port_number == c.portNumber);
                    let swInfo = '';
                    if (pp && pp.connected_switch_id) {
                        const sw = switches.find(s => s.id == pp.connected_switch_id);
                        swInfo = ` → ${sw ? escapeHtml(sw.name) : 'SW' + pp.connected_switch_id} Port ${pp.connected_switch_port || '?'}`;
                    }
                    existingHtml += `<div style="font-size:0.9rem;color:#e2e8f0;margin-bottom:4px;"><i class="fas fa-th-large" style="color:#fcd34d;margin-right:4px;"></i>Panel ${escapeHtml(c.panelLetter)} Port ${c.portNumber}${swInfo}</div>`;
                });
                existingHtml += `</div>`;
            }
            if (directConn && directConn.device_name) {
                existingHtml += `<div style="background:rgba(139,92,246,0.08);border-left:4px solid #8b5cf6;border-radius:8px;padding:12px;margin-bottom:12px;">
                    <div style="color:#8b5cf6;font-weight:700;margin-bottom:4px;"><i class="fas fa-desktop"></i> Direkt Bağlantı</div>
                    <div style="font-size:0.9rem;color:#e2e8f0;">${escapeHtml(directConn.device_name)}</div>
                    ${directConn.notes ? `<div style="font-size:0.8rem;color:#94a3b8;margin-top:4px;">${escapeHtml(directConn.notes)}</div>` : ''}
                </div>`;
            }

            // Patch panels in same rack
            const rackPanels = patchPanels.filter(p => p.rack_id == rd.rack_id);
            const rackSwitchList = switches.filter(s => s.rack_id == rd.rack_id);

            const modal = document.createElement('div');
            modal.className = 'modal-overlay active';
            modal.id = 'hubsw-port-edit-modal';
            modal.style.zIndex = '1100';
            modal.innerHTML = `
                <div class="modal" style="max-width:540px;">
                    <div class="modal-header" style="background:linear-gradient(135deg,#1a1400,#2d1f00);border-bottom:2px solid #d97706;">
                        <h3 class="modal-title" style="color:#fbbf24;"><i class="fas fa-sitemap" style="margin-right:6px;"></i>${escapeHtml(rd.name)} — Port ${portNum}</h3>
                        <button class="modal-close" onclick="closeHubSwPortEditModal()">&times;</button>
                    </div>
                    <div class="modal-body" style="padding:20px;">
                        ${existingHtml || '<p style="color:#64748b;margin-bottom:12px;font-size:0.9rem;">Bu port henüz bağlı değil.</p>'}
                        <form id="hubsw-port-edit-form">
                            <input type="hidden" id="hpe-rd-id" value="${rdId}">
                            <input type="hidden" id="hpe-port-num" value="${portNum}">
                            <div class="form-group" style="margin-bottom:14px;">
                                <label class="form-label"><i class="fas fa-plug"></i> Bağlantı Türü</label>
                                <select id="hpe-conn-type" class="form-control" onchange="onHpeConnTypeChange()">
                                    <option value="patch_panel">Patch Panel Portu</option>
                                    <option value="switch">Switch Portu</option>
                                    <option value="device">Cihaz (Serbest)</option>
                                </select>
                            </div>
                            <!-- Patch Panel section -->
                            <div id="hpe-patch-section">
                                <div class="form-group" style="margin-bottom:14px;">
                                    <label class="form-label"><i class="fas fa-th-large"></i> Patch Panel</label>
                                    <select id="hpe-panel-sel" class="form-control" onchange="onHpePanelChange()">
                                        <option value="">Panel Seçin</option>
                                        ${rackPanels.map(p => `<option value="${p.id}">Panel ${escapeHtml(p.panel_letter)} (${p.total_ports}P)</option>`).join('')}
                                    </select>
                                </div>
                                <div class="form-group" id="hpe-panel-port-row" style="display:none;margin-bottom:14px;">
                                    <label class="form-label"><i class="fas fa-hashtag"></i> Port Numarası</label>
                                    <select id="hpe-panel-port-sel" class="form-control"></select>
                                </div>
                            </div>
                            <!-- Switch section (hidden) -->
                            <div id="hpe-switch-section" style="display:none;">
                                <div class="form-group" style="margin-bottom:14px;">
                                    <label class="form-label"><i class="fas fa-network-wired"></i> Switch</label>
                                    <select id="hpe-switch-sel" class="form-control" onchange="onHpeSwitchChange()">
                                        <option value="">Switch Seçin</option>
                                        ${rackSwitchList.map(s => `<option value="${s.id}">${escapeHtml(s.name)}</option>`).join('')}
                                    </select>
                                </div>
                                <div class="form-group" id="hpe-switch-port-row" style="display:none;margin-bottom:14px;">
                                    <label class="form-label"><i class="fas fa-hashtag"></i> Switch Port</label>
                                    <select id="hpe-switch-port-sel" class="form-control"></select>
                                </div>
                            </div>
                            <!-- Device section (hidden) -->
                            <div id="hpe-device-section" style="display:none;">
                                <div class="form-group" style="margin-bottom:14px;">
                                    <label class="form-label"><i class="fas fa-desktop"></i> Cihaz Adı</label>
                                    <input type="text" id="hpe-device-name" class="form-control" placeholder="Örn: PC-MUHASEBE-01" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--dark);color:var(--text);" value="${directConn ? escapeHtml(directConn.device_name || '') : ''}">
                                </div>
                                <div class="form-group" style="margin-bottom:14px;">
                                    <label class="form-label"><i class="fas fa-sticky-note"></i> Not (isteğe bağlı)</label>
                                    <input type="text" id="hpe-notes" class="form-control" placeholder="Ek bilgi..." style="width:100%;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--dark);color:var(--text);" value="${directConn ? escapeHtml(directConn.notes || '') : ''}">
                                </div>
                            </div>
                            <div style="display:flex;gap:10px;margin-top:20px;">
                                ${(directConn) ? `<button type="button" class="btn btn-danger" style="flex:1;" onclick="deleteHubSwPortConnection(${rdId},${portNum})"><i class="fas fa-unlink"></i> Bağlantıyı Sil</button>` : ''}
                                <button type="button" class="btn btn-secondary" style="flex:1;" onclick="closeHubSwPortEditModal()">İptal</button>
                                <button type="submit" class="btn btn-primary" style="flex:1;"><i class="fas fa-save"></i> Kaydet</button>
                            </div>
                        </form>
                    </div>
                </div>`;
            document.body.appendChild(modal);

            document.getElementById('hubsw-port-edit-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                await saveHubSwPortConnection();
            });
        }

        function closeHubSwPortEditModal() {
            const m = document.getElementById('hubsw-port-edit-modal');
            if (m) m.remove();
        }

        function onHpeConnTypeChange() {
            const t = document.getElementById('hpe-conn-type').value;
            document.getElementById('hpe-patch-section').style.display  = t === 'patch_panel' ? '' : 'none';
            document.getElementById('hpe-switch-section').style.display = t === 'switch'      ? '' : 'none';
            document.getElementById('hpe-device-section').style.display = t === 'device'      ? '' : 'none';
        }

        function onHpePanelChange() {
            const panelId = document.getElementById('hpe-panel-sel').value;
            const portRow = document.getElementById('hpe-panel-port-row');
            const portSel = document.getElementById('hpe-panel-port-sel');
            portSel.innerHTML = '<option value="">Port Seçin</option>';
            if (!panelId) { portRow.style.display = 'none'; return; }
            const panel = patchPanels.find(p => p.id == panelId);
            const total = panel ? (panel.total_ports || 24) : 24;
            for (let p = 1; p <= total; p++) portSel.innerHTML += `<option value="${p}">${p}</option>`;
            portRow.style.display = '';
        }

        function onHpeSwitchChange() {
            const swId = document.getElementById('hpe-switch-sel').value;
            const portRow = document.getElementById('hpe-switch-port-row');
            const portSel = document.getElementById('hpe-switch-port-sel');
            portSel.innerHTML = '<option value="">Port Seçin</option>';
            if (!swId) { portRow.style.display = 'none'; return; }
            const sw = switches.find(s => s.id == swId);
            const total = sw ? (sw.ports || 24) : 24;
            for (let p = 1; p <= total; p++) portSel.innerHTML += `<option value="${p}">${p}</option>`;
            portRow.style.display = '';
        }

        async function saveHubSwPortConnection() {
            const rdId   = parseInt(document.getElementById('hpe-rd-id').value);
            const portNum= parseInt(document.getElementById('hpe-port-num').value);
            const cType  = document.getElementById('hpe-conn-type').value;

            if (cType === 'patch_panel') {
                // Save by updating the patch panel port's connection_details
                const panelId  = parseInt(document.getElementById('hpe-panel-sel').value || '0');
                const panelPort= parseInt(document.getElementById('hpe-panel-port-sel').value || '0');
                if (!panelId || !panelPort) { showToast('Panel ve port seçiniz', 'error'); return; }
                const rd = (rackDevices || []).find(d => d.id == rdId);
                const resp = await fetch('actions/savePatchPanel.php', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({
                        action: 'save_port_connection',
                        panelId, panelType: 'patch', portNumber: panelPort,
                        connType: 'rack_device',
                        rackDeviceId: rdId,
                        rackDeviceName: rd ? rd.name : '',
                        rackDevicePort: portNum
                    })
                });
                const data = await resp.json();
                if (data.success) {
                    showToast('Bağlantı kaydedildi', 'success');
                    closeHubSwPortEditModal();
                    await loadData();
                    // Re-open port modal so it reflects the new connection
                    openHubSwPortModal(rdId);
                } else {
                    showToast(data.error || 'Kayıt hatası', 'error');
                }
            } else if (cType === 'switch') {
                // Save by updating the patch port connecting switch → hub SW
                // For simplicity, store as a direct connection via saveHubSwConnection.php
                const swId   = parseInt(document.getElementById('hpe-switch-sel').value || '0');
                const swPort = parseInt(document.getElementById('hpe-switch-port-sel').value || '0');
                if (!swId || !swPort) { showToast('Switch ve port seçiniz', 'error'); return; }
                const sw = switches.find(s => s.id == swId);
                const resp = await fetch('actions/saveHubSwConnection.php', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({ rdId, portNum, connType: 'switch', swId, swPort, deviceName: sw ? sw.name + ' Port ' + swPort : '' })
                });
                const data = await resp.json();
                if (data.success) {
                    showToast('Bağlantı kaydedildi', 'success');
                    closeHubSwPortEditModal();
                    await loadData();
                    openHubSwPortModal(rdId);
                } else { showToast(data.error || 'Kayıt hatası', 'error'); }
            } else {
                // Device (free text)
                const deviceName = (document.getElementById('hpe-device-name').value || '').trim();
                const notes      = (document.getElementById('hpe-notes').value || '').trim();
                if (!deviceName) { showToast('Cihaz adı gereklidir', 'error'); return; }
                const resp = await fetch('actions/saveHubSwConnection.php', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({ rdId, portNum, connType: 'device', deviceName, notes })
                });
                const data = await resp.json();
                if (data.success) {
                    showToast('Bağlantı kaydedildi', 'success');
                    closeHubSwPortEditModal();
                    await loadData();
                    openHubSwPortModal(rdId);
                } else { showToast(data.error || 'Kayıt hatası', 'error'); }
            }
        }

        async function deleteHubSwPortConnection(rdId, portNum) {
            if (!confirm('Bu bağlantıyı silmek istediğinize emin misiniz?')) return;
            const resp = await fetch('actions/saveHubSwConnection.php', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({ action: 'delete', rdId, portNum })
            });
            const data = await resp.json();
            if (data.success) {
                showToast('Bağlantı silindi', 'success');
                closeHubSwPortEditModal();
                await loadData();
                openHubSwPortModal(rdId);
            } else { showToast(data.error || 'Silme hatası', 'error'); }
        }

        // Panel detayında port tıklama - GÜNCELLENMIŞ
        window.editPatchPort = function(panelId, portNumber) {
            openPanelPortEditModal(panelId, portNumber, 'patch');
        };

        window.editFiberPort = function(panelId, portNumber) {
            openPanelPortEditModal(panelId, portNumber, 'fiber');
        };

        // ============================================
        // TOOLTIP YÖNETİMİ VE PORT HOVER LISTENER'LARI
        // ============================================

        // --- Tooltip yönetimi ve port hover listener'ları ---

        // Unwrap nested JSON in core_switch_name (can happen when sync writes the whole JSON blob as the name)
        function unwrapCoreSwitchName(name) {
          const MAX_UNWRAP_DEPTH = 500;
          let depth = MAX_UNWRAP_DEPTH;
          while (name && name.charAt(0) === '{' && depth-- > 0) {
            try {
              const inner = JSON.parse(name);
              if (!inner || typeof inner.core_switch_name !== 'string') break;
              if (inner.core_switch_name === name) break;
              name = inner.core_switch_name;
            } catch(e) { break; }
          }
          return name;
        }

        // Returns true only for strings that look like a valid MAC address (12 hex digits).
        // Rejects switch-name+port strings like "SW8-MARKETING port 40".
        function isValidMacAddress(value) {
          if (!value) return false;
          const clean = (value + '').replace(/[:\-. ]/g, '');
          return /^[0-9a-fA-F]{12}$/.test(clean);
        }

        (function() {
          // Tek bir tooltip elementi kullanıyoruz
          let globalTooltip = null;
          function ensureTooltip() {
            if (globalTooltip) return globalTooltip;
            globalTooltip = document.createElement('div');
            globalTooltip.className = 'tooltip';
            // minimal inline style to ensure visibility; you can keep your CSS rules instead
            globalTooltip.style.position = 'fixed';
            globalTooltip.style.zIndex = 99999;
            globalTooltip.style.pointerEvents = 'none';
            globalTooltip.style.transition = 'opacity 0.12s ease';
            globalTooltip.style.opacity = '0';
            globalTooltip.style.minWidth = '200px';
            globalTooltip.style.maxWidth = '360px';
            globalTooltip.style.boxSizing = 'border-box';
            globalTooltip.style.padding = '10px';
            globalTooltip.style.borderRadius = '8px';
            globalTooltip.style.background = 'rgba(15,23,42,0.95)';
            globalTooltip.style.color = '#e2e8f0';
            globalTooltip.style.border = '1px solid rgba(59,130,246,0.15)';
            document.body.appendChild(globalTooltip);
            return globalTooltip;
          }

          // Pozisyonlama: pencere sınırlarını kontrol eder
          function positionTooltip(x, y) {
            const t = ensureTooltip();
            const pad = 12;
            const rect = t.getBoundingClientRect();
            const vw = window.innerWidth;
            const vh = window.innerHeight;
            let left = x + 12;
            let top = y + 12;
            // overflow right
            if (left + rect.width + pad > vw) {
              left = x - rect.width - 12;
              if (left < pad) left = pad;
            }
            // overflow bottom
            if (top + rect.height + pad > vh) {
              top = y - rect.height - 12;
              if (top < pad) top = pad;
            }
            t.style.left = left + 'px';
            t.style.top = top + 'px';
          }

          // İçerik üretici — data-* veya element parametresine göre içerik oluşturur

          function buildTooltipContent(el) {
  const port = el.getAttribute('data-port') || el.dataset.port || (el.querySelector('.port-number') ? el.querySelector('.port-number').textContent.trim() : '');
  const device = el.getAttribute('data-device') || el.dataset.device || el.querySelector('.port-device')?.textContent?.trim() || '';
  const type = el.getAttribute('data-type') || el.dataset.type || el.querySelector('.port-type')?.textContent?.trim() || '';
  const ip = el.getAttribute('data-ip') || el.dataset.ip || '';
  const mac = el.getAttribute('data-mac') || el.dataset.mac || '';
  const portAlias = el.getAttribute('data-port-alias') || el.dataset.portAlias || '';
  const connPreserved = el.getAttribute('data-connection') || el.dataset.connection || '';
  const connJson = el.getAttribute('data-connection-json') || el.dataset.connectionJson || '';
  const multi = el.getAttribute('data-multiple') || el.dataset.multiple || '';
  // Fallback core switch connection info from snmp_core_ports (set when
  // connection_info_preserved has no virtual_core JSON).
  const coreConn = el.getAttribute('data-core-conn') || '';

  const portLabel2 = el.getAttribute('data-port-label') || '';
  const portDisplay = portLabel2 ? portLabel2 : port;
  let html = `<div style="font-weight:700;margin-bottom:6px;">Port: ${escapeHtml(portDisplay)} ${type ? '(' + escapeHtml(type) + ')' : ''}</div>`;
  if (portAlias) html += `<div style="margin-bottom:4px;font-size:0.82rem;color:#38bdf8;"><i class="fas fa-tag" style="font-size:0.75rem;margin-right:3px;"></i><strong>Port Açıklaması:</strong> ${escapeHtml(portAlias)}</div>`;
  // When the stored device name is a purely numeric ID (e.g. room number "2116"),
  // prefer portAlias over it; suppress entirely when both are empty.
  const _devNumeric = /^\d+$/.test(device);
  const _devDisplay = _devNumeric ? (portAlias || '') : device;
  if (_devDisplay) html += `<div style="margin-bottom:4px;"><strong>Cihaz:</strong> ${escapeHtml(_devDisplay)}</div>`;
  if (ip) html += `<div style="margin-bottom:4px;"><strong>IP:</strong> <span style="font-family:monospace">${escapeHtml(ip)}</span></div>`;
  if (mac) {
    // For hub ports, mac may be a long comma-separated list; wrap it properly.
    const macDisplay = mac.split(',').map(m => m.trim()).filter(Boolean).join(', ');
    html += `<div style="margin-bottom:4px;"><strong>MAC:</strong> <span style="font-family:monospace;word-break:break-all;overflow-wrap:break-word;">${escapeHtml(macDisplay)}</span></div>`;
  }

  // Panel bilgisi
  const panelId     = el.getAttribute('data-panel-id')     || '';
  const panelPort   = el.getAttribute('data-panel-port')   || '';
  const panelLetter = el.getAttribute('data-panel-letter') || '';
  const panelRack   = el.getAttribute('data-panel-rack')   || '';
  if (panelId) {
    html += `<div style="margin-top:6px;padding:6px 8px;background:rgba(139,92,246,0.12);border:1px solid rgba(139,92,246,0.25);border-radius:6px;">`;
    html += `<div style="color:#c4b5fd;font-weight:700;margin-bottom:4px;font-size:0.82rem;"><i class="fas fa-th-large"></i> Panel Bağlantısı</div>`;
    if (panelLetter) html += `<div style="font-size:0.82rem;"><strong>Panel:</strong> ${escapeHtml(panelLetter)} — Port ${panelPort}</div>`;
    if (panelRack)   html += `<div style="font-size:0.82rem;"><strong>Rack:</strong> ${escapeHtml(panelRack)}</div>`;
    html += `</div>`;
  }

  // Always show "Mevcut Bağlantı" block
  html += `<div style="margin-top:8px; padding:8px; background: rgba(15,23,42,0.6); border-radius:6px;">`;
  html += `<div style="color: #10b981; font-weight:700; margin-bottom:6px;"><i class="fas fa-link"></i> Mevcut Bağlantı</div>`;

  if (multi) {
    try {
      const arr = JSON.parse(multi);
      if (Array.isArray(arr) && arr.length > 0) {
        arr.slice(0,6).forEach((it, idx) => {
          const rawName = (it.device || it.name || '').trim();
          const isGeneric = rawName === '' || /^Cihaz\s+\d+$/i.test(rawName);
          // When device name is purely numeric (room/device ID), prefer:
          //   1. portAlias (snmp ifAlias, e.g. "IP-TV")
          // When device name is purely numeric (room/device ID), show the numeric
          // hostname as-is in Mevcut Bağlantı so the user sees "3233" not the alias.
          // The alias (e.g. "Ruby 3233") is already shown on the port card directly.
          const isPurelyNumeric = /^\d+$/.test(rawName);
          const _genericTypes = new Set(['ETHERNET','BOŞ','FIBER','DEVICE','HUB','']);
          const _typeUsable = type && !_genericTypes.has(type.toUpperCase());
          const displayName = isPurelyNumeric
            ? rawName   // show numeric hostname (e.g. "3233") — alias already on card
            : (isGeneric ? (it.ip || it.mac || rawName || `Cihaz ${idx+1}`) : rawName);
          const nameLabel = (isGeneric && !isPurelyNumeric)
            ? `<span style="color:#94a3b8;">${escapeHtml(displayName)}</span>`
            : `<strong style="color:#e2e8f0;">${escapeHtml(displayName)}</strong>`;
          // Show only hostname/IP — MAC omitted from tooltip; no N: prefix
          html += `<div style="font-size:0.85rem;">${nameLabel}</div>`;
        });
      } else {
        html += `<div style="font-size:0.85rem; color:var(--text-light);">Hub bilgisi mevcut değil</div>`;
      }
    } catch(e) {
      html += `<div style="font-size:0.85rem;">${escapeHtml(multi)}</div>`;
    }
  } else if (connJson) {
    try {
      const parsed = JSON.parse(connJson);
      if (Array.isArray(parsed)) {
        parsed.slice(0,6).forEach((it, idx) => {
          // Show only hostname in tooltip Mevcut Bağlantı — no N: prefix
          html += `<div style="font-size:0.85rem;">${escapeHtml(it.device || it.name || '')}</div>`;
        });
      } else if (parsed && parsed.type === 'virtual_core') {
        const coreName = unwrapCoreSwitchName(parsed.core_switch_name || '');
        html += `<div style="font-size:0.9rem;">
          <i class="fas fa-server" style="color:#fbbf24;margin-right:4px;"></i>
          <strong style="color:#fbbf24;">${escapeHtml(coreName)}</strong>
          <span style="color:#94a3b8;"> | </span>
          <span style="color:#e2e8f0;">${escapeHtml(parsed.core_port_label || '')}</span>
        </div>`;
      } else if (parsed && parsed.type === 'virtual_core_reverse') {
        html += `<div style="font-size:0.9rem;">
          <i class="fas fa-network-wired" style="color:#34d399;margin-right:4px;"></i>
          <strong style="color:#34d399;">${escapeHtml(parsed.edge_switch_name || '')}</strong>
          <span style="color:#94a3b8;"> port </span>
          <span style="color:#e2e8f0;">${escapeHtml(String(parsed.edge_port_no || ''))}</span>
        </div>`;
      } else if (parsed && (parsed.edge_switch_name || parsed.edge_port_no)) {
        // Defensive fallback: JSON has edge switch fields but missing/wrong "type"
        html += `<div style="font-size:0.9rem;">
          <i class="fas fa-network-wired" style="color:#34d399;margin-right:4px;"></i>
          <strong style="color:#34d399;">${escapeHtml(parsed.edge_switch_name || '')}</strong>
          <span style="color:#94a3b8;"> port </span>
          <span style="color:#e2e8f0;">${escapeHtml(String(parsed.edge_port_no || ''))}</span>
        </div>`;
      } else {
        html += `<div style="font-size:0.85rem;">${escapeHtml(JSON.stringify(parsed))}</div>`;
      }
    } catch(e) {
      html += `<div style="font-size:0.85rem;">${escapeHtml(connJson)}</div>`;
    }
  } else if (connPreserved) {
    // Check if this is a virtual core switch connection (JSON with type="virtual_core")
    try {
      const vcParsed = JSON.parse(connPreserved);
      if (vcParsed && vcParsed.type === 'virtual_core') {
        const vcName = unwrapCoreSwitchName(vcParsed.core_switch_name || '');
        html += `<div style="font-size:0.9rem;">
          <i class="fas fa-server" style="color:#fbbf24;margin-right:4px;"></i>
          <strong style="color:#fbbf24;">${escapeHtml(vcName)}</strong>
          <span style="color:#94a3b8;"> | </span>
          <span style="color:#e2e8f0;">${escapeHtml(vcParsed.core_port_label || '')}</span>
        </div>`;
      } else if (vcParsed && vcParsed.type === 'virtual_core_reverse') {
        // Reverse connection: this is a core switch port showing which edge switch is connected
        html += `<div style="font-size:0.9rem;">
          <i class="fas fa-network-wired" style="color:#34d399;margin-right:4px;"></i>
          <strong style="color:#34d399;">${escapeHtml(vcParsed.edge_switch_name || '')}</strong>
          <span style="color:#94a3b8;"> port </span>
          <span style="color:#e2e8f0;">${escapeHtml(String(vcParsed.edge_port_no || ''))}</span>
        </div>`;
      } else if (vcParsed && (vcParsed.edge_switch_name || vcParsed.edge_port_no)) {
        // Defensive fallback: JSON has edge switch fields but missing/wrong "type"
        html += `<div style="font-size:0.9rem;">
          <i class="fas fa-network-wired" style="color:#34d399;margin-right:4px;"></i>
          <strong style="color:#34d399;">${escapeHtml(vcParsed.edge_switch_name || '')}</strong>
          <span style="color:#94a3b8;"> port </span>
          <span style="color:#e2e8f0;">${escapeHtml(String(vcParsed.edge_port_no || ''))}</span>
        </div>`;
      } else if (coreConn) {
        // connPreserved is non-JSON raw text (e.g. "Te1/1/2") but snmp_core_ports has
        // the real core switch connection — show that instead of the raw LLDP text.
        html += _buildCoreConnHtml(coreConn);
      } else {
        html += `<div style="font-size:0.9rem;">${escapeHtml(connPreserved)}</div>`;
      }
    } catch(e) {
      // connPreserved is plain text (not JSON) — prefer coreConn fallback if available
      if (coreConn) {
        html += _buildCoreConnHtml(coreConn);
      } else {
        html += `<div style="font-size:0.9rem;">${escapeHtml(connPreserved)}</div>`;
      }
    }
  } else if (coreConn) {
    // No connPreserved at all but snmp_core_ports has the connection info
    html += _buildCoreConnHtml(coreConn);
  } else {
    // No JSON connection data – fall back to plain device info when available
    if (device && device.trim()) {
      html += `<div style="font-size:0.85rem;font-weight:600;color:#e2e8f0;">${escapeHtml(device.trim())}</div>`;
      if (type && type.trim() && type.trim() !== 'ETHERNET' && type.trim() !== 'BOŞ' && type.trim() !== 'FIBER') {
        html += `<div style="font-size:0.78rem;color:#94a3b8;margin-top:2px;">${escapeHtml(type.trim())}</div>`;
      }
      if (ip && ip.trim()) {
        html += `<div style="font-size:0.78rem;font-family:monospace;color:#7dd3fc;margin-top:2px;">${escapeHtml(ip.split(',')[0].trim())}</div>`;
      }
    } else {
      html += `<div style="font-size:0.85rem; color:var(--text-light);">Bağlantı bilgisi yok</div>`;
    }
  }

  html += `</div>`;
  return html;
}

// Render a coreConn string ("CoreSW | PortLabel", just "CoreSW", or a
// virtual_core JSON object) as an amber core-switch connection block.
function _buildCoreConnHtml(coreConn) {
  // Handle JSON-format core_switch_name (e.g. stored as virtual_core JSON object)
  if (coreConn.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(coreConn);
      if (parsed && parsed.type === 'virtual_core') {
        const swName    = unwrapCoreSwitchName(parsed.core_switch_name || '');
        const portLabel = parsed.core_port_label || '';
        if (portLabel) {
          return `<div style="font-size:0.9rem;">
            <i class="fas fa-server" style="color:#fbbf24;margin-right:4px;"></i>
            <strong style="color:#fbbf24;">${escapeHtml(swName)}</strong>
            <span style="color:#94a3b8;"> | </span>
            <span style="color:#e2e8f0;">${escapeHtml(portLabel)}</span>
          </div>`;
        }
        return `<div style="font-size:0.9rem;">
          <i class="fas fa-server" style="color:#fbbf24;margin-right:4px;"></i>
          <strong style="color:#fbbf24;">${escapeHtml(swName)}</strong>
        </div>`;
      }
    } catch(e) {}
  }
  const pipeIdx = coreConn.indexOf('|');
  if (pipeIdx !== -1) {
    const swName   = coreConn.substring(0, pipeIdx).trim();
    const portLabel = coreConn.substring(pipeIdx + 1).trim();
    return `<div style="font-size:0.9rem;">
      <i class="fas fa-server" style="color:#fbbf24;margin-right:4px;"></i>
      <strong style="color:#fbbf24;">${escapeHtml(swName)}</strong>
      <span style="color:#94a3b8;"> | </span>
      <span style="color:#e2e8f0;">${escapeHtml(portLabel)}</span>
    </div>`;
  }
  return `<div style="font-size:0.9rem;">
    <i class="fas fa-server" style="color:#fbbf24;margin-right:4px;"></i>
    <strong style="color:#fbbf24;">${escapeHtml(coreConn)}</strong>
  </div>`;
}

          function escapeHtml(s) {
            return (s || '').toString().replace(/[&<>"'`]/g, function(m){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[m]; });
          }

          // Show / hide helpers
          function showTooltipForElement(el, clientX, clientY) {
            const t = ensureTooltip();
            t.innerHTML = buildTooltipContent(el);
            t.style.opacity = '1';
            positionTooltip(clientX, clientY);
          }
          function hideTooltip() {
            if (!globalTooltip) return;
            globalTooltip.style.opacity = '0';
          }

          // Attach hover listeners to all .port-item elements (or selector you use)
          window.attachPortHoverTooltips = function(selector = '.port-item') {
            // ensure tooltip exists
            ensureTooltip();

            const nodes = document.querySelectorAll(selector);
            nodes.forEach(node => {
              // Skip if already attached – avoids double-listeners without cloneNode
              // (cloneNode was previously used here but it destroys all other event
              //  listeners on the element, including the SNMP detail modal click handler)
              if (node.dataset.tooltipAttached === '1') return;
              node.dataset.tooltipAttached = '1';

              node.addEventListener('mouseenter', function(e) {
                const style = window.getComputedStyle(node);
                if (style.pointerEvents === 'none' || style.visibility === 'hidden' || style.display === 'none') return;
                showTooltipForElement(node, e.clientX, e.clientY);
              });
              node.addEventListener('mousemove', function(e) {
                positionTooltip(e.clientX, e.clientY);
              });
              node.addEventListener('mouseleave', function() {
                hideTooltip();
              });
              node.addEventListener('focus', function(e) {
                const rect = node.getBoundingClientRect();
                showTooltipForElement(node, rect.left + 10, rect.top + 10);
              });
              node.addEventListener('blur', function() {
                hideTooltip();
              });
            });
          };

          // Auto-run after DOMContentLoaded if ports exist
          document.addEventListener('DOMContentLoaded', function() {
            // small delay to allow initial renderers
            setTimeout(function(){ attachPortHoverTooltips(); }, 300);
          });

        })();

        // Utility Functions
        function showToast(message, type = 'info', duration = 5000) {
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.innerHTML = `
                <div class="toast-header">
                    <div class="toast-title">${type.toUpperCase()}</div>
                    <button class="toast-close">&times;</button>
                </div>
                <div class="toast-body">${message}</div>
            `;
            
            toastContainer.appendChild(toast);
            
            const closeBtn = toast.querySelector('.toast-close');
            closeBtn.addEventListener('click', () => {
                toast.remove();
            });
            
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.remove();
                }
            }, duration);
        }

        function showLoading() {
            loadingScreen.classList.remove('hidden');
        }

        function hideLoading() {
            loadingScreen.classList.add('hidden');
        }

        // ============================================
        // SLOT YÖNETİMİ FONKSİYONLARI
        // ============================================

        function updateAvailableSlots(rackId, type = 'switch', currentPosition = null) {
            console.log(`updateAvailableSlots çağrıldı: rackId=${rackId}, type=${type}, currentPosition=${currentPosition}`);
            
            const selectId = type === 'switch' ? 'switch-position' : 'panel-position';
            const positionSelect = document.getElementById(selectId);
            
            if (!positionSelect) {
                console.error('Position select element bulunamadı:', selectId);
                return;
            }
            
            const rack = racks.find(r => r.id == rackId);
            if (!rack) {
                console.error('Rack bulunamadı:', rackId);
                positionSelect.innerHTML = '<option value="">Rack bulunamadı</option>';
                positionSelect.disabled = true;
                return;
            }
            
            const maxSlots = rack.slots || 42;
            console.log('Rack bulundu:', rack.name, 'Max slots:', maxSlots);
            
            // Bu rack'teki dolu slotları bul
            const usedSlots = new Set();
            
            // Switch'lerin kullandığı slotlar
            switches.forEach(sw => {
                if (sw.rack_id == rackId && sw.position_in_rack) {
                    if (currentPosition === null || sw.position_in_rack != currentPosition) {
                        const startSlot = parseInt(sw.position_in_rack);
                        // Core switch'ler 8U yer kaplar
                        const slotsUsed = (sw.is_core == 1 || sw.is_core === true || sw.is_core === '1') ? 8 : 1;
                        for (let s = startSlot; s < startSlot + slotsUsed; s++) {
                            usedSlots.add(s);
                        }
                    }
                }
            });
            
            // Patch panellerin kullandığı slotlar
            if (typeof patchPanels !== 'undefined' && patchPanels && patchPanels.length > 0) {
                patchPanels.forEach(panel => {
                    if (panel.rack_id == rackId && panel.position_in_rack) {
                        if (currentPosition === null || panel.position_in_rack != currentPosition) {
                            usedSlots.add(parseInt(panel.position_in_rack));
                        }
                    }
                });
            }
            
            // Fiber panellerin kullandığı slotlar
            if (typeof fiberPanels !== 'undefined' && fiberPanels && fiberPanels.length > 0) {
                fiberPanels.forEach(panel => {
                    if (panel.rack_id == rackId && panel.position_in_rack) {
                        if (currentPosition === null || panel.position_in_rack != currentPosition) {
                            usedSlots.add(parseInt(panel.position_in_rack));
                        }
                    }
                });
            }
            
            console.log('Dolu slotlar:', Array.from(usedSlots));
            
            // Select'i doldur
            positionSelect.innerHTML = '<option value="">Slot Seçin (Opsiyonel)</option>';
            
            for (let i = 1; i <= maxSlots; i++) {
                const option = document.createElement('option');
                option.value = i;
                
                if (usedSlots.has(i)) {
                    option.textContent = `Slot ${i} ⛔ DOLU`;
                    option.disabled = true;
                    option.style.color = '#ef4444';
                    option.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
                } else {
                    option.textContent = `Slot ${i} ✓ BOŞ`;
                }
                
                // Mevcut pozisyon varsa seçili yap
                if (currentPosition && i == currentPosition) {
                    option.selected = true;
                    option.textContent = `Slot ${i} ⭐ MEVCUT`;
                    option.style.color = '#10b981';
                }
                
                positionSelect.appendChild(option);
            }
            
            positionSelect.disabled = false;
            console.log('Slot listesi güncellendi, toplam:', maxSlots, 'dolu:', usedSlots.size);
        }

        function updateAvailableSlotsForFiber(rackId, currentPosition = null) {
            const positionSelect = document.getElementById('fiber-panel-position');
            
            if (!positionSelect) return;
            
            const rack = racks.find(r => r.id == rackId);
            if (!rack) {
                positionSelect.innerHTML = '<option value="">Rack bulunamadı</option>';
                positionSelect.disabled = true;
                return;
            }
            
            const maxSlots = rack.slots || 42;
            
            // Dolu slotları bul
            const usedSlots = new Set();
            
            switches.forEach(sw => {
                if (sw.rack_id == rackId && sw.position_in_rack) {
                    const startSlot = parseInt(sw.position_in_rack);
                    const slotsUsed = (sw.is_core == 1 || sw.is_core === true || sw.is_core === '1') ? 8 : 1;
                    for (let s = startSlot; s < startSlot + slotsUsed; s++) {
                        usedSlots.add(s);
                    }
                }
            });
            
            patchPanels.forEach(panel => {
                if (panel.rack_id == rackId && panel.position_in_rack) {
                    usedSlots.add(parseInt(panel.position_in_rack));
                }
            });

            fiberPanels.forEach(panel => {
                if (panel.rack_id == rackId && panel.position_in_rack) {
                    if (currentPosition === null || panel.position_in_rack != currentPosition) {
                        usedSlots.add(parseInt(panel.position_in_rack));
                    }
                }
            });
            
            // Select'i doldur
            positionSelect.innerHTML = '<option value="">Slot Seçin</option>';
            
            for (let i = 1; i <= maxSlots; i++) {
                const option = document.createElement('option');
                option.value = i;
                
                if (usedSlots.has(i)) {
                    option.textContent = `Slot ${i} ⛔ DOLU`;
                    option.disabled = true;
                    option.style.color = '#ef4444';
                    option.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
                } else {
                    option.textContent = `Slot ${i} ✓ BOŞ`;
                }
                
                if (currentPosition && i == currentPosition) {
                    option.selected = true;
                    option.textContent = `Slot ${i} ⭐ MEVCUT`;
                    option.style.color = '#10b981';
                }
                
                positionSelect.appendChild(option);
            }
            
            positionSelect.disabled = false;
        }

        // ============================================
        // HUB PORT FONKSİYONLARI
        // ============================================

        function showHubDetails(switchId, portNo, connection) {
            const modal = document.getElementById('hub-modal');
            const content = document.getElementById('hub-content');
            const titleEl = document.getElementById('hub-modal-title');

            try {
                // ── Collect hub devices ──────────────────────────────────────────
                let hubDevices = [];
                const rawConn = connection.multiple_connections || connection.connection_info || '';
                if (rawConn && rawConn !== '[]' && rawConn !== 'null') {
                    try { hubDevices = JSON.parse(rawConn); } catch(e) {}
                }
                if (!hubDevices.length && Array.isArray(connection.connections)) {
                    hubDevices = connection.connections;
                }
                // Fallback: build from raw ip/mac strings
                if (!hubDevices.length && (connection.ip || connection.mac)) {
                    const ips  = (connection.ip  || '').split(',').map(s=>s.trim()).filter(Boolean);
                    const macs = (connection.mac || '').split(',').map(s=>s.trim()).filter(Boolean);
                    const len  = Math.max(ips.length, macs.length);
                    for (let i = 0; i < len; i++) {
                        hubDevices.push({ device: `Cihaz ${i+1}`, ip: ips[i]||'', mac: macs[i]||'', type:'DEVICE' });
                    }
                }

                // Augment hubDevices with any extra MACs from the raw mac column
                // (SNMP may see more MACs than registered in multiple_connections)
                if (connection.mac) {
                    const rawMacs = connection.mac.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
                    const registeredMacs = new Set(hubDevices.map(d => (d.mac || '').trim().toUpperCase()).filter(Boolean));
                    rawMacs.forEach(mac => {
                        if (!registeredMacs.has(mac)) {
                            // Try to fill into an existing hostname-only entry before creating a duplicate
                            const emptyMacEntry = hubDevices.find(
                                d => !d.mac && d.device && !/^Cihaz\s+\d+$/i.test(d.device)
                            );
                            if (emptyMacEntry) {
                                emptyMacEntry.mac = mac;
                            } else {
                                hubDevices.push({ device: `Cihaz ${hubDevices.length+1}`, ip: '', mac: mac, type:'DEVICE' });
                            }
                        }
                    });
                }

                const hubName  = connection.hub_name || `Hub - Port ${portNo}`;

                // A hub device is "active" if it has an IP, a MAC, or a
                // meaningful (non-generic) device name that was saved by the user.
                function _isHubDevActive(d) {
                    if (d.ip || d.mac) return true;
                    const name = (d.device || '').trim();
                    return name.length > 0 && !/^Cihaz\s*\d*$/i.test(name);
                }

                const total    = hubDevices.length || 1;
                const active   = hubDevices.filter(_isHubDevActive).length;
                const passive  = total - active;

                if (titleEl) titleEl.textContent = hubName;

                // Store device list globally so onclick can reference by index safely
                window._hubVisDevices = hubDevices;

                // ── Build chassis header ─────────────────────────────────────────
                let html = `
                <div style="background:linear-gradient(135deg,#1e293b,#0f172a);border-radius:14px;padding:14px 18px;margin-bottom:14px;border:1px solid rgba(245,158,11,0.35);">
                    <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;">
                        <div style="width:44px;height:44px;background:linear-gradient(135deg,#f59e0b,#d97706);border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                            <i class="fas fa-network-wired" style="color:#fff;font-size:1.2rem;"></i>
                        </div>
                        <div>
                            <div style="font-weight:700;color:var(--text);font-size:1rem;">${hubName}</div>
                            <div style="font-size:0.78rem;color:var(--text-light);">
                                Switch Port ${portNo} &nbsp;·&nbsp; ${total} port
                            </div>
                        </div>
                        <div style="margin-left:auto;display:flex;gap:8px;">
                            <div style="background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.4);border-radius:8px;padding:5px 12px;text-align:center;">
                                <div style="font-size:1.1rem;font-weight:700;color:#10b981;">${active}</div>
                                <div style="font-size:0.65rem;color:#10b981;">Aktif</div>
                            </div>
                            <div style="background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.35);border-radius:8px;padding:5px 12px;text-align:center;">
                                <div style="font-size:1.1rem;font-weight:700;color:#ef4444;">${passive}</div>
                                <div style="font-size:0.65rem;color:#ef4444;">Pasif</div>
                            </div>
                        </div>
                    </div>
                    <!-- LED bar -->
                    <div style="height:6px;background:#0f172a;border-radius:3px;overflow:hidden;">
                        <div style="height:100%;width:${total>0?Math.round(active/total*100):0}%;background:linear-gradient(90deg,#10b981,#34d399);border-radius:3px;transition:width .5s;"></div>
                    </div>
                </div>`;

                // ── Hub chassis visual ───────────────────────────────────────────
                html += `<div style="background:#0f172a;border-radius:12px;border:2px solid rgba(245,158,11,0.3);padding:16px;margin-bottom:14px;">`;

                // Responsive column count
                const cols = total <= 8 ? total : total <= 16 ? Math.ceil(total/2) : 12;
                html += `<div id="hub-port-grid" style="display:grid;grid-template-columns:repeat(${cols},minmax(44px,1fr));gap:6px;">`;

                hubDevices.forEach((dev, idx) => {
                    const isActive = _isHubDevActive(dev);
                    const devName  = dev.device || `Cihaz ${idx+1}`;
                    const ledColor = isActive ? '#10b981' : '#ef4444';
                    const bgStyle  = isActive
                        ? 'background:linear-gradient(135deg,rgba(16,185,129,0.25),rgba(16,185,129,0.12));border-color:#10b981;'
                        : 'background:linear-gradient(135deg,rgba(239,68,68,0.18),rgba(239,68,68,0.08));border-color:#ef4444;';
                    const safeLabel = devName;
                    const pulse = isActive ? 'animation:hub-led-pulse 2s infinite;' : '';

                    html += `
                    <div class="hub-vis-port" data-hidx="${idx}" data-hub-active="${isActive ? '1' : '0'}"
                         style="border-radius:8px;border:2px solid;${bgStyle}cursor:pointer;padding:6px 4px;text-align:center;
                                transition:transform .15s,box-shadow .15s;position:relative;"
                         onmouseenter="this.style.transform='scale(1.08)';this.style.boxShadow='0 4px 14px rgba(0,0,0,0.4)'"
                         onmouseleave="this.style.transform='scale(1)';this.style.boxShadow='none'"
                         onclick="showHubPortDetail(this)">
                        <div style="width:8px;height:8px;border-radius:50%;background:${ledColor};
                                    box-shadow:0 0 6px ${ledColor};margin:0 auto 4px;${pulse}"></div>
                        <div style="font-size:0.7rem;font-weight:700;color:var(--text);">${idx+1}</div>
                        <div style="font-size:0.58rem;color:${ledColor};margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${safeLabel}">${safeLabel}</div>
                    </div>`;
                });

                html += `</div></div>`; // close grid + chassis

                // ── Selected port detail panel ───────────────────────────────────
                html += `<div id="hub-port-detail-panel" style="display:none;background:rgba(15,23,42,0.7);border-radius:10px;
                              border:1px solid rgba(56,189,248,0.3);padding:14px;margin-bottom:14px;"></div>`;

                // ── Action row ───────────────────────────────────────────────────
                html += `
                <div style="display:flex;gap:10px;margin-top:6px;">
                    <button class="btn btn-primary" style="flex:1;"
                            onclick="closeHubModal();openSnmpPortDetailModal(${switchId},${portNo})">
                        <i class="fas fa-info-circle"></i> Port Detayları
                    </button>
                    <button class="btn btn-secondary" style="flex:1;" onclick="closeHubModal()">
                        <i class="fas fa-times"></i> Kapat
                    </button>
                </div>`;

                content.innerHTML = html;
                modal.classList.add('active');

                // ── Async Device Import enrichment ───────────────────────────────
                // For each hub device:
                //  • If it has a MAC  → look up by MAC in Device Import.
                //    Found  → fill IP from registry, mark green.
                //    Missing → mark red + create "unknown MAC" alarm.
                //  • If it has no MAC but has a meaningful name
                //                   → look up by name in Device Import.
                //    Found  → populate MAC + IP from registry, mark green.
                //    Missing → keep red.
                hubDevices.forEach((dev, idx) => {
                    const mac  = (dev.mac  || '').trim();
                    const name = (dev.device || '').trim();
                    const isGenericName = /^Cihaz\s*\d*$/i.test(name);

                    function _applyRegistryData(regDev) {
                        if (!window._hubVisDevices || !window._hubVisDevices[idx]) return;
                        if (regDev.device_name) window._hubVisDevices[idx].device = regDev.device_name;
                        if (regDev.ip_address)  window._hubVisDevices[idx].ip     = regDev.ip_address;
                        if (regDev.mac_address) window._hubVisDevices[idx].mac    = regDev.mac_address;

                        // Propagate enriched device names back to the port element's data-multiple
                        // so the hover tooltip shows real names after hub modal has been opened.
                        const portEl = document.querySelector(`#detail-ports-grid .port-item[data-switch-id="${switchId}"][data-port="${portNo}"]`);
                        if (portEl) {
                            portEl.setAttribute('data-multiple', JSON.stringify(window._hubVisDevices));
                        }

                        // Update port cell label
                        const cell = document.querySelector(`.hub-vis-port[data-hidx="${idx}"]`);
                        if (!cell) return;
                        const labelEl = cell.querySelector('div:last-child');
                        if (labelEl && regDev.device_name) {
                            const n = regDev.device_name;
                            labelEl.textContent = n;
                            labelEl.title = n;
                        }
                        // Make cell green (known device)
                        if (cell.dataset.hubActive !== '1') {
                            cell.dataset.hubActive = '1';
                            cell.style.background  = 'linear-gradient(135deg,rgba(16,185,129,0.25),rgba(16,185,129,0.12))';
                            cell.style.borderColor = '#10b981';
                            const ledDot = cell.querySelector('div:first-child');
                            if (ledDot) {
                                ledDot.style.background  = '#10b981';
                                ledDot.style.boxShadow   = '0 0 6px #10b981';
                                ledDot.style.animation   = 'hub-led-pulse 2s infinite';
                            }
                        }
                        // If panel is open for this device, refresh it
                        const panel = document.getElementById('hub-port-detail-panel');
                        if (panel && panel.style.display !== 'none') {
                            const sel = document.querySelector('.hub-vis-port.selected');
                            if (sel && parseInt(sel.dataset.hidx, 10) === idx) {
                                showHubPortDetail(sel);
                            }
                        }
                    }

                    function _markUnknown(macAddr) {
                        const cell = document.querySelector(`.hub-vis-port[data-hidx="${idx}"]`);
                        if (cell) {
                            cell.dataset.hubActive = '0';
                            cell.style.background  = 'linear-gradient(135deg,rgba(239,68,68,0.18),rgba(239,68,68,0.08))';
                            cell.style.borderColor = '#ef4444';
                            const ledDot = cell.querySelector('div:first-child');
                            if (ledDot) {
                                ledDot.style.background  = '#ef4444';
                                ledDot.style.boxShadow   = '0 0 6px #ef4444';
                                ledDot.style.animation   = '';
                            }
                        }
                        // Alarm creation intentionally removed: the background SNMP worker
                        // detects unknown/missing MACs and generates alarms automatically.
                        // Creating alarms from the View Port modal caused duplicate noise.
                    }

                    if (mac) {
                        // MAC-based lookup
                        fetch(`api/device_import_api.php?action=get&mac=${encodeURIComponent(mac)}`)
                            .then(r => r.json())
                            .then(data => {
                                if (data.success && data.device) {
                                    _applyRegistryData(data.device);
                                } else {
                                    _markUnknown(mac);
                                }
                            })
                            .catch(err => console.debug('Hub DI lookup by MAC failed:', err));
                    } else if (name && !isGenericName) {
                        // Name-based lookup (device was entered without MAC)
                        fetch(`api/device_import_api.php?action=get_by_name&name=${encodeURIComponent(name)}`)
                            .then(r => r.json())
                            .then(data => {
                                if (data.success && data.device) {
                                    _applyRegistryData(data.device);
                                }
                                // If not found by name, keep current state (no alarm – no MAC to alarm on)
                            })
                            .catch(err => console.debug('Hub DI lookup by name failed:', err));
                    }
                });

            } catch (error) {
                console.error('Hub detay yükleme hatası:', error);
                content.innerHTML = `
                    <div style="text-align:center;padding:40px;color:#ef4444;">
                        <i class="fas fa-exclamation-triangle" style="font-size:2rem;margin-bottom:15px;"></i>
                        <p>Hub bilgileri yüklenemedi</p>
                    </div>
                `;
            }
        }

        // Show detail panel for a clicked hub port cell
        function showHubPortDetail(el) {
            // Deselect previous
            document.querySelectorAll('.hub-vis-port.selected').forEach(p => {
                p.classList.remove('selected');
                p.style.outline = '';
            });
            el.classList.add('selected');
            el.style.outline = '2px solid #38bdf8';

            const idx = parseInt(el.dataset.hidx, 10);
            const dev = (window._hubVisDevices || [])[idx];
            if (isNaN(idx) || !dev) return;

            const panel = document.getElementById('hub-port-detail-panel');
            if (!panel) return;

            // Prefer the data-hub-active attribute (set after DI enrichment) for status,
            // fall back to field presence for initial render before enrichment completes.
            const activeAttr = el.dataset.hubActive;
            const isActive = activeAttr === '1' ? true
                           : activeAttr === '0' ? false
                           : !!(dev.ip || dev.mac ||
                                (dev.device && dev.device.trim() && !/^Cihaz\s*\d*$/i.test(dev.device.trim())));
            const statusColor  = isActive ? '#10b981' : '#ef4444';
            const statusBorder = isActive ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)';
            const statusText   = isActive ? 'Aktif' : 'Pasif';

            let lastSeenHtml = '';
            const ls = dev.last_seen || dev.updated_at || '';
            if (ls) {
                lastSeenHtml = `
                <div style="display:flex;align-items:center;gap:8px;margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.07);">
                    <i class="fas fa-clock" style="color:#94a3b8;font-size:0.8rem;"></i>
                    <span style="font-size:0.8rem;color:var(--text-light);">Son görülme:</span>
                    <span style="font-size:0.8rem;color:var(--text);font-family:monospace;">${ls}</span>
                </div>`;
            }

            const devName = dev.device || `Cihaz ${idx+1}`;
            panel.style.display = 'block';
            panel.innerHTML = `
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                <div style="width:10px;height:10px;border-radius:50%;background:${statusColor};box-shadow:0 0 8px ${statusColor};flex-shrink:0;"></div>
                <span style="font-weight:700;color:var(--text);">${devName}</span>
                <span style="margin-left:auto;padding:2px 10px;border-radius:10px;font-size:0.72rem;
                      background:${isActive?'rgba(16,185,129,0.18)':'rgba(239,68,68,0.15)'};
                      color:${statusColor};border:1px solid ${statusBorder};">${statusText}</span>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                <div style="background:rgba(16,185,129,0.08);border-radius:8px;padding:8px 10px;">
                    <div style="font-size:0.7rem;color:var(--text-light);margin-bottom:3px;"><i class="fas fa-network-wired"></i> IP Adresi</div>
                    <div style="font-family:monospace;font-size:0.85rem;color:${dev.ip?'#10b981':'#64748b'};">${dev.ip || '—'}</div>
                </div>
                <div style="background:rgba(59,130,246,0.08);border-radius:8px;padding:8px 10px;">
                    <div style="font-size:0.7rem;color:var(--text-light);margin-bottom:3px;"><i class="fas fa-ethernet"></i> MAC Adresi</div>
                    <div style="font-family:monospace;font-size:0.85rem;color:${dev.mac?'#3b82f6':'#64748b'};">${dev.mac || '—'}</div>
                </div>
            </div>
            ${lastSeenHtml}`;
        }

        // Hub verilerini CSV olarak dışa aktarma fonksiyonu
        function exportHubData(switchId, portNo) {
            const connection = getPortConnection(switchId, portNo);
            let hubData = [];
            
            if (connection && connection.multiple_connections) {
                try {
                    hubData = JSON.parse(connection.multiple_connections);
                } catch (e) {
                    console.error('Export data parse error:', e);
                }
            }
            
            if (hubData.length === 0) {
                showToast('Dışa aktarılacak veri bulunamadı', 'warning');
                return;
            }
            
            // CSV başlıkları
            let csvContent = "No,Cihaz,IP Adresi,MAC Adresi,Tür\n";
            
            // Verileri ekle
            hubData.forEach((device, index) => {
                const row = [
                    index + 1,
                    `"${device.device || `Cihaz ${index + 1}`}"`,
                    `"${device.ip || ''}"`,
                    `"${device.mac || ''}"`,
                    `"${device.type || 'DEVICE'}"`
                ];
                csvContent += row.join(',') + '\n';
            });
            
            // CSV dosyasını indir
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            
            const switchName = switches.find(s => s.id == switchId)?.name || 'Switch';
            link.setAttribute('href', url);
            link.setAttribute('download', `Hub_Port_${portNo}_${switchName}_${new Date().toISOString().split('T')[0]}.csv`);
            link.style.visibility = 'hidden';
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            showToast('Hub verileri CSV olarak indirildi', 'success');
        }

        // Hub port düzenleme modalını aç
        function editHubPort(switchId, portNo) {
            const modal = document.getElementById('hub-edit-modal');
            const form = document.getElementById('hub-form');
            
            // Mevcut hub bilgilerini yükle
            const connection = getPortConnection(switchId, portNo);
            
            document.getElementById('hub-switch-id').value = switchId;
            document.getElementById('hub-port-number').value = portNo;
            document.getElementById('hub-name').value = connection.hub_name || '';
            document.getElementById('hub-type').value = connection.type || 'ETHERNET';
            
            // Cihaz listesini yükle
            const devicesList = document.getElementById('hub-devices-list');
            devicesList.innerHTML = '';
            
            let hubDevices = [];
            if (connection && connection.multiple_connections) {
                try {
                    hubDevices = JSON.parse(connection.multiple_connections);
                } catch (e) {
                    console.error('Hub devices parse error:', e);
                }
            }
            
            if (hubDevices.length === 0) {
                // Boşsa 5 cihaz ekle
                for (let i = 0; i < 5; i++) {
                    hubDevices.push({
                        device: '',
                        ip: '',
                        mac: '',
                        type: 'DEVICE'
                    });
                }
            }
            
            // Scroll için container
            const scrollContainer = document.createElement('div');
            scrollContainer.style.cssText = `
                max-height: 400px;
                overflow-y: auto;
                padding-right: 5px;
            `;
            
            // Cihaz başlığı
            const headerRow = document.createElement('div');
            headerRow.style.cssText = `
                display: grid;
                grid-template-columns: 0.5fr 2fr 2fr 2fr 1fr;
                gap: 10px;
                margin-bottom: 10px;
                padding: 10px;
                background: rgba(56, 189, 248, 0.1);
                border-radius: 8px;
                font-weight: bold;
                color: var(--text-light);
            `;
            headerRow.innerHTML = `
                <div>#</div>
                <div>Cihaz Adı</div>
                <div>IP Adresi</div>
                <div>MAC Adresi</div>
                <div>Tür</div>
            `;
            scrollContainer.appendChild(headerRow);
            
            // Cihaz satırlarını ekle
            hubDevices.forEach((device, index) => {
                addDeviceRowToContainer(scrollContainer, index, device);
            });
            
            devicesList.appendChild(scrollContainer);
            
            modal.classList.add('active');
        }

        function addDeviceRowToContainer(container, index, device = { device: '', ip: '', mac: '', type: 'DEVICE' }) {
            const row = document.createElement('div');
            row.className = 'hub-device-row';
            row.style.cssText = `
                display: grid;
                grid-template-columns: 0.5fr 2fr 2fr 2fr 1fr 0.5fr;
                gap: 10px;
                margin-bottom: 10px;
                align-items: center;
                padding: 10px;
                background: rgba(15, 23, 42, 0.3);
                border-radius: 8px;
            `;
            
            row.innerHTML = `
                <div style="text-align: center; color: var(--text-light); font-weight: bold;">
                    ${index + 1}
                </div>
                
                <input type="text" class="form-control hub-device-name" 
                       placeholder="Cihaz adı" value="${device.device || ''}"
                       style="min-width: 150px;">
                
                <input type="text" class="form-control hub-device-ip" 
                       placeholder="192.168.1.1" value="${device.ip || ''}"
                       style="min-width: 150px; font-family: monospace;">
                
                <input type="text" class="form-control hub-device-mac" 
                       placeholder="aa:bb:cc:dd:ee:ff" value="${device.mac || ''}"
                       style="min-width: 150px; font-family: monospace;">
                
                <select class="form-control hub-device-type" style="min-width: 120px;">
                    <option value="DEVICE" ${device.type === 'DEVICE' ? 'selected' : ''}>DEVICE</option>
                    <option value="AP" ${device.type === 'AP' ? 'selected' : ''}>AP</option>
                    <option value="IPTV" ${device.type === 'IPTV' ? 'selected' : ''}>IPTV</option>
                    <option value="PHONE" ${device.type === 'PHONE' ? 'selected' : ''}>PHONE</option>
                    <option value="PRINTER" ${device.type === 'PRINTER' ? 'selected' : ''}>PRINTER</option>
                    <option value="SERVER" ${device.type === 'SERVER' ? 'selected' : ''}>SERVER</option>
                    <option value="CAMERA" ${device.type === 'CAMERA' ? 'selected' : ''}>CAMERA</option>
                </select>
                
                <button type="button" class="btn btn-danger btn-sm remove-device" 
                        style="padding: 8px; min-width: 40px;" title="Sil">
                    <i class="fas fa-times"></i>
                </button>
            `;
            
            container.appendChild(row);
        }

        // Hub modalını kapat
        function closeHubModal() {
            document.getElementById('hub-modal').classList.remove('active');
        }

        // Hub edit modalını kapat
        function closeHubEditModal() {
            document.getElementById('hub-edit-modal').classList.remove('active');
        }

        // Tip rengini al
        function getTypeColor(type) {
            const colors = {
                'HUB': '#f59e0b',
                'DEVICE': '#10b981',
                'AP': '#ef4444',
                'IPTV': '#8b5cf6',
                'PHONE': '#3b82f6',
                'PRINTER': '#06b6d4',
                'SERVER': '#8b5cf6',
                'CAMERA': '#ec4899',
                'ETHERNET': '#3b82f6',
                'FIBER': '#8b5cf6'
            };
            return colors[type] || '#64748b';
        }

        // Port bağlantısını al
        function getPortConnection(switchId, portNo) {
            const connections = portConnections[switchId] || [];
            return connections.find(c => c.port == portNo) || {};
        }

        // Port display'ini hub için güncelle
        function updatePortDisplay(portElement, connection) {
            // Eski H ikonlarını temizle
            const oldHubIcon = portElement.querySelector('.hub-icon');
            if (oldHubIcon) {
                oldHubIcon.remove();
            }
            
            // Hub portuysa H ikonu ekle
            if (connection && connection.is_hub == 1) {
                // H ikonu ekle
                const hubIcon = document.createElement('div');
                hubIcon.className = 'hub-icon';
                hubIcon.textContent = 'HUB';
                hubIcon.title = 'Hub Portu - Tıkla for detay';
                
                portElement.appendChild(hubIcon);
                
                // Port sınıfını ekle
                portElement.classList.add('hub-port');
                
                // Port tipini HUB yap
                const typeElement = portElement.querySelector('.port-type');
                if (typeElement) {
                    typeElement.textContent = 'HUB';
                    typeElement.className = 'port-type hub';
                }
            }
        }

        // Hub port tıklama event'ını ayarla
        function setupHubPortClick(portElement, switchId, portNo, connection) {
            // Eski event listener'ları temizle
            const newPortElement = portElement.cloneNode(true);
            portElement.parentNode.replaceChild(newPortElement, portElement);
            
            // Hub ikonuna tıklama
            const hubIcon = newPortElement.querySelector('.hub-icon');
            if (hubIcon && connection && connection.is_hub == 1) {
                hubIcon.addEventListener('click', function(e) {
                    e.stopPropagation();
                    showHubDetails(switchId, portNo, connection);
                });
            }
            
            // Port'a tıklama
            newPortElement.addEventListener('click', function(e) {
                if (e.target.closest('.hub-icon')) return;
                
                if (connection && connection.is_hub == 1) {
                    showHubDetails(switchId, portNo, connection);
                } else {
                    openPortModal(switchId, portNo);
                }
            });
        }
// Rack silme yardımcı fonksiyonu
function confirmDeleteRack(rackId) {
    if (!confirm('Bu rack ve içindeki tüm switch / paneller silinecek. Emin misiniz?')) return;
    deleteRack(rackId); // deleteRack fonksiyonu index.php içinde zaten tanımlıydı
}
        // ============================================
        // FIBER PANEL FONKSİYONLARI
        // ============================================

        // Fiber panel ekleme fonksiyonu
        async function saveFiberPanel(formData) {
            try {
                showLoading();
                
                console.log('Fiber panel kaydediliyor:', formData);
                
                const response = await fetch('actions/saveFiberPanel.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });
                
                const responseText = await response.text();
                console.log('Fiber panel response:', responseText);
                
                let result;
                try {
                    result = JSON.parse(responseText);
                } catch (parseError) {
                    console.error('JSON parse error:', parseError, 'Response:', responseText);
                    throw new Error('Sunucudan geçersiz yanıt alındı');
                }
                
                if (result.success) {
                    showToast('Fiber panel başarıyla eklendi: ' + result.panelLetter, 'success');
                    
                    // Modal'ı kapat
                    document.getElementById('fiber-panel-modal').classList.remove('active');
                    
                    // Verileri yenile
                    await loadData();
                    
                    // Racks sayfasını yenile
                    if (document.getElementById('page-racks').classList.contains('active')) {
                        loadRacksPage();
                    }
                    
                    return result;
                } else {
                    throw new Error(result.message || 'Fiber panel eklenemedi');
                }
                
            } catch (error) {
                console.error('Fiber panel ekleme hatası:', error);
                showToast('Fiber panel eklenemedi: ' + error.message, 'error');
                throw error;
            } finally {
                hideLoading();
            }
        }

        // Fiber panel modal'ını açma fonksiyonu
        function openFiberPanelModal(rackId = null) {
            console.log('openFiberPanelModal çağrıldı, rackId:', rackId);
            
            const modal = document.getElementById('fiber-panel-modal');
            const rackSelect = document.getElementById('fiber-panel-rack-select');
            const title = document.getElementById('fiber-panel-title');
            
            // Formu resetle
            document.getElementById('fiber-panel-form').reset();
            
            // Rack seçeneklerini doldur
            rackSelect.innerHTML = '<option value="">Rack Seçin</option>';
            racks.forEach(rack => {
                const option = document.createElement('option');
                option.value = rack.id;
                option.textContent = `${rack.name} (${rack.location})`;
                rackSelect.appendChild(option);
            });
            
            if (rackId) {
                title.textContent = 'Fiber Panel Ekle';
                document.getElementById('fiber-panel-rack-id').value = rackId;
                rackSelect.value = rackId;
                rackSelect.disabled = true;
                
                // Slot listesini güncelle
                updateAvailableSlotsForFiber(rackId);
            } else {
                title.textContent = 'Fiber Panel Ekle';
                rackSelect.disabled = false;
                const positionSelect = document.getElementById('fiber-panel-position');
                if (positionSelect) {
                    positionSelect.innerHTML = '<option value="">Önce Rack Seçin</option>';
                    positionSelect.disabled = true;
                }
            }
            
            modal.classList.add('active');
        }

        function openSwitchModal(switchToEdit = null) {
            console.log('openSwitchModal çağrıldı, switchToEdit:', switchToEdit);
            
            const modal = document.getElementById('switch-modal');
            const form = document.getElementById('switch-form');
            const title = modal.querySelector('.modal-title');
            const rackSelect = document.getElementById('switch-rack');
            
            // Clear form
            form.reset();
            
            // Populate rack select
            rackSelect.innerHTML = '';
            racks.forEach(rack => {
                const option = document.createElement('option');
                option.value = rack.id;
                option.textContent = `${rack.name} (${rack.location})`;
                rackSelect.appendChild(option);
            });
            
            if (switchToEdit) {
                title.textContent = 'Switch Düzenle';
                document.getElementById('switch-id').value = switchToEdit.id;
                document.getElementById('switch-is-core').value = (switchToEdit.is_core == 1 || switchToEdit.is_core === true || switchToEdit.is_core === '1') ? '1' : '0';
                document.getElementById('switch-is-virtual').value = (switchToEdit.is_virtual == 1 || switchToEdit.is_virtual === true || switchToEdit.is_virtual === '1') ? '1' : '0';
                document.getElementById('switch-name').value = switchToEdit.name;
                document.getElementById('switch-brand').value = switchToEdit.brand || '';
                document.getElementById('switch-model').value = switchToEdit.model || '';
                document.getElementById('switch-ports').value = switchToEdit.ports;
                document.getElementById('switch-status').value = switchToEdit.status;
                document.getElementById('switch-ip').value = switchToEdit.ip || '';

                // Sanal switch için port sayısı zorunlu değil - mevcut değeri koru
                const isVirt = (switchToEdit.is_virtual == 1 || switchToEdit.is_virtual === true || switchToEdit.is_virtual === '1');
                const portsField = document.getElementById('switch-ports');
                const portsGroup = portsField ? portsField.closest('.form-group') : null;
                if (isVirt) {
                    portsField.removeAttribute('required');
                    if (portsGroup) {
                        portsGroup.style.opacity = '0.5';
                        portsGroup.title = 'Sanal switch için port sayısı değiştirilemez';
                        portsField.disabled = true;
                    }
                } else {
                    portsField.setAttribute('required', 'required');
                    if (portsGroup) { portsGroup.style.opacity = ''; portsGroup.title = ''; portsField.disabled = false; }
                }
                
                if (switchToEdit.rack_id) {
                    rackSelect.value = switchToEdit.rack_id;
                    // Slot listesini güncelle
                    updateAvailableSlots(switchToEdit.rack_id, 'switch', switchToEdit.position_in_rack);
                }
            } else {
                title.textContent = 'Yeni Switch Ekle';
                document.getElementById('switch-id').value = '';
                // Yeni switch için port sayısı alanını sıfırla (zorunlu + aktif)
                const portsFieldN = document.getElementById('switch-ports');
                if (portsFieldN) {
                    portsFieldN.setAttribute('required', 'required');
                    portsFieldN.disabled = false;
                    const pg = portsFieldN.closest('.form-group');
                    if (pg) { pg.style.opacity = ''; pg.title = ''; }
                }
                if (racks.length > 0) {
                    rackSelect.value = racks[0].id;
                    updateAvailableSlots(racks[0].id, 'switch');
                }
            }
            
            modal.classList.add('active');
        }

        function openPatchPanelModal(rackId = null) {
            console.log('openPatchPanelModal çağrıldı, rackId:', rackId);
            
            const modal = document.getElementById('patch-panel-modal');
            const rackSelect = document.getElementById('panel-rack-select');
            
            // Rack seçeneklerini doldur
            rackSelect.innerHTML = '<option value="">Rack Seçin</option>';
            racks.forEach(rack => {
                const option = document.createElement('option');
                option.value = rack.id;
                option.textContent = `${rack.name} (${rack.location})`;
                rackSelect.appendChild(option);
            });
            
            if (rackId) {
                document.getElementById('patch-panel-rack-id').value = rackId;
                rackSelect.value = rackId;
                rackSelect.disabled = true;
                updateAvailableSlots(rackId, 'panel');
            } else {
                rackSelect.disabled = false;
                const positionSelect = document.getElementById('panel-position');
                if (positionSelect) {
                    positionSelect.innerHTML = '<option value="">Önce Rack Seçin</option>';
                    positionSelect.disabled = true;
                }
            }
            
            modal.classList.add('active');
        }

        // ============================================
        // GÜNCELLENMİŞ PORT MODAL FONKSİYONLARI
        // ============================================

        // VLAN ID → Cihaz Türü eşleme tablosu (modül seviyesinde sabit)
        const VLAN_TYPE_MAP = {
            30: 'SANTRAL',
            50: 'DEVICE',
            70: 'AP',
            80: 'KAMERA',
            120: 'OTOMASYON',
            130: 'IPTV',
            140: 'SANTRAL',
            254: 'DEVICE'
        };

       function openPortModal(switchId, portNumber = null) {
    const modal = document.getElementById('port-modal');
    const form = document.getElementById('port-form');

    // Tip güvenliği: switchId string gelebilir -> sayıya çevir
    const switchIdNum = switchId !== null && switchId !== undefined ? Number(switchId) : NaN;

    // Bulurken number ile karşılaştır (hem number hem string sorununu ortadan kaldır)
    const sw = switches.find(s => Number(s.id) === switchIdNum);

    if (!sw) {
        console.error('openPortModal: Switch bulunamadı. switchId=', switchId, 'switches=', switches);
        showToast('Switch verisi bulunamadı veya henüz yüklenmedi. Lütfen sayfayı yenileyip tekrar deneyin.', 'error', 7000);
        return;
    }

    const connections = portConnections[sw.id] || [];
    const existingConnection = connections.find(c => Number(c.port) === Number(portNumber));
            
            form.reset();
            document.getElementById('port-switch-id').value = switchId;
            document.getElementById('port-switch-rack-id').value = sw.rack_id;
            
            // Port numarası ve tipi
            const isCoreSw = sw.is_core == 1 || sw.is_core === true || sw.is_core === '1';
            const isFiberPort = isCoreSw ? true : portNumber > (sw.ports - 4);
            
            if (portNumber) {
                document.getElementById('port-number').value = portNumber;
                document.getElementById('port-no-display').value = `Port ${portNumber} ${isFiberPort ? '(Fiber)' : '(Ethernet)'}`;
            }
            
            // Mevcut bağlantı bilgilerini yükle
            if (existingConnection) {
                modal.querySelector('.modal-title').textContent = 'Port Bağlantısını Düzenle';
                
                // VLAN bilgisi SNMP'den varsa, VLAN seçeneğini otomatik seç
                // Debug logging - Tarayıcı console'da (F12) görmek için
                console.log('Port VLAN Debug:', {
                    port_no: portNumber,
                    snmp_vlan_id: existingConnection.snmp_vlan_id,
                    snmp_vlan_name: existingConnection.snmp_vlan_name,
                    current_type: existingConnection.type
                });
                
                let portType = existingConnection.type || 'BOŞ';
                if (existingConnection.snmp_vlan_id && existingConnection.snmp_vlan_id > 1) {
                    const vlanId = parseInt(existingConnection.snmp_vlan_id);
                    if (VLAN_TYPE_MAP[vlanId]) {
                        // Bilinen VLAN → doğrudan cihaz türüne eşle
                        portType = VLAN_TYPE_MAP[vlanId];
                        console.log(`✅ VLAN ${vlanId} → ${portType} otomatik seçildi`);
                    } else {
                        // Bilinmeyen VLAN → "VLAN X" seçeneğini dene, yoksa mevcut type'ı koru
                        const vlanOption = `VLAN ${vlanId}`;
                        const selectElement = document.getElementById('port-type');
                        const optionExists = Array.from(selectElement.options).some(opt => opt.value === vlanOption);
                        if (optionExists) {
                            portType = vlanOption;
                            console.log(`✅ VLAN ${vlanId} seçeneği bulundu`);
                        } else {
                            console.log(`⚠️ VLAN ${vlanId} eşlemesi yok, mevcut type kullanılıyor`);
                        }
                    }
                }
                
                document.getElementById('port-type').value = portType;
                // VLAN rozeti
                const vlanBadge = document.getElementById('modal-vlan-badge');
                const rawVlan = existingConnection.snmp_vlan_id;
                if (rawVlan && parseInt(rawVlan) > 1) {
                    vlanBadge.textContent = 'SNMP VLAN ' + parseInt(rawVlan);
                    vlanBadge.style.display = 'inline-block';
                    vlanBadge.style.background = '#0d6efd';
                } else {
                    vlanBadge.style.display = 'none';
                }
                document.getElementById('port-device').value = existingConnection.device || '';
                document.getElementById('port-ip').value = existingConnection.ip || '';
                document.getElementById('port-mac').value = existingConnection.mac || '';
                
                // ÖNEMLİ: CONNECTION INFO'YU YÜKLE - HER ZAMAN GÖRÜNÜR
                const connectionInfo = existingConnection.connection_info_preserved || existingConnection.connection_info || '';
                document.getElementById('port-connection-info').value = connectionInfo;
                
                // Panel bağlantısı varsa yükle
                if (existingConnection.connected_panel_id) {
                    const panelType = existingConnection.panel_type || 'patch';
                    document.getElementById('panel-type-select').value = panelType;
                    
                    // Panel listesini yükle
                    loadPanelsForRack(sw.rack_id, panelType, isFiberPort);
                    
                    // Panel ve port seçimini ayarla
                    setTimeout(() => {
                        document.getElementById('patch-panel-select').value = existingConnection.connected_panel_id;
                        document.getElementById('patch-port-number').value = existingConnection.connected_panel_port;
                        
                        // Önizleme güncelle
                        updatePanelPreview();
                    }, 100);
                }
            } else {
                modal.querySelector('.modal-title').textContent = 'Port Bağlantısı Ekle';
                document.getElementById('port-type').value = isFiberPort ? 'FIBER' : 'ETHERNET';
                const vlanBadgeNew = document.getElementById('modal-vlan-badge');
                if (vlanBadgeNew) vlanBadgeNew.style.display = 'none';
            }
            
            // Panel tipi değişim eventi
            setupPanelTypeChangeEvent(sw.rack_id, isFiberPort);
            
            // Core switch bölümünü FIBER portlar için göster
            const isCoreSwitchSw = sw.is_core == 1 || sw.is_core === true || sw.is_core === '1';
            setupCoreSwitchSection(isFiberPort, isCoreSwitchSw, existingConnection);
            
            // Device Import lookup - MAC adresi değiştiğinde otomatik doldur
            setupDeviceImportLookup();
            
            // Mevcut MAC varsa ve device import kaydı varsa lookup yap
            if (existingConnection && existingConnection.mac) {
                lookupDeviceByMac(existingConnection.mac);
            }
            
            modal.classList.add('active');
        }

        // Panel tipi değiştiğinde panelleri yükle
        function setupPanelTypeChangeEvent(rackId, isFiberPort) {
            const panelTypeSelect = document.getElementById('panel-type-select');
            const panelSelect = document.getElementById('patch-panel-select');
            const portInput = document.getElementById('patch-port-number');
            const fiberWarning = document.getElementById('fiber-warning');
            const patchWarning = document.getElementById('patch-warning');
            
            // Önceki event'i temizle
            panelTypeSelect.replaceWith(panelTypeSelect.cloneNode(true));
            const newPanelTypeSelect = document.getElementById('panel-type-select');
            
            newPanelTypeSelect.addEventListener('change', function() {
                const panelType = this.value;
                
                // Uyarıları göster/gizle
                fiberWarning.style.display = 'none';
                patchWarning.style.display = 'none';
                
                if (panelType === 'fiber' && !isFiberPort) {
                    fiberWarning.style.display = 'block';
                    panelSelect.disabled = true;
                    portInput.disabled = true;
                    panelSelect.innerHTML = '<option value="">Fiber paneller sadece fiber portlara bağlanabilir</option>';
                    return;
                }
                
                if (panelType === 'patch' && isFiberPort) {
                    patchWarning.style.display = 'block';
                    panelSelect.disabled = true;
                    portInput.disabled = true;
                    panelSelect.innerHTML = '<option value="">Patch paneller fiber portlara bağlanamaz</option>';
                    return;
                }
                
                if (panelType) {
                    loadPanelsForRack(rackId, panelType, isFiberPort);
                } else {
                    panelSelect.innerHTML = '<option value="">Önce panel tipi seçin</option>';
                    panelSelect.disabled = true;
                    portInput.disabled = true;
                }
            });
        }

        // Core Switch bağlantı bölümü kurulumu
        function setupCoreSwitchSection(isFiberPort, isCoreSwitchSelf, existingConnection) {
            const group = document.getElementById('core-switch-connection-group');
            const swSel = document.getElementById('core-switch-select');
            const portSel = document.getElementById('core-switch-port-select');
            const preview = document.getElementById('core-switch-preview');
            const previewText = document.getElementById('core-switch-preview-text');
            const connInfoEl = document.getElementById('port-connection-info');

            if (!group || !swSel || !portSel) return;

            // Core switch portlarının kendi modalında gösterme
            if (isCoreSwitchSelf || !isFiberPort) {
                group.style.display = 'none';
                return;
            }

            group.style.display = '';

            // Core switchleri doldur
            const coreSwitches = (typeof switches !== 'undefined' ? switches : [])
                .filter(s => s.is_core == 1 || s.is_core === true || s.is_core === '1');

            swSel.innerHTML = '<option value="">Core Switch Seç</option>';
            coreSwitches.forEach(cs => {
                const opt = document.createElement('option');
                opt.value = cs.id;
                opt.textContent = cs.name + ' (' + (cs.model || 'Core') + ')';
                swSel.appendChild(opt);
            });

            function updateCorePorts() {
                const csId = Number(swSel.value);
                if (!csId) {
                    portSel.innerHTML = '<option value="">Önce switch seçin</option>';
                    portSel.disabled = true;
                    preview.style.display = 'none';
                    return;
                }
                const cs = coreSwitches.find(s => Number(s.id) === csId);
                portSel.innerHTML = '<option value="">Port Seç</option>';
                portSel.disabled = false;
                const csPorts = (portConnections[csId] || []);
                for (let p = 1; p <= (cs ? cs.ports : 48); p++) {
                    const cpConn = csPorts.find(x => x.port === p);
                    const swSlot = cs ? (() => { const m = cs.name && cs.name.match(/-(\d+)$/); return m ? parseInt(m[1], 10) : 1; })() : 1;
                    const coreMod = p <= 48 ? 1 : 2;
                    const corePWithin = ((p - 1) % 48) + 1;
                    const lbl = (cpConn && cpConn.port_label) ? cpConn.port_label : ('TwentyFiveGigE' + swSlot + '/' + coreMod + '/0/' + corePWithin);
                    const opt = document.createElement('option');
                    opt.value = p;
                    opt.dataset.label = lbl;
                    opt.textContent = lbl + (cpConn && cpConn.type !== 'BOŞ' && cpConn.device ? ' ← ' + cpConn.device : '');
                    portSel.appendChild(opt);
                }
                updateCorePreview();
            }

            function updateCorePreview() {
                const csId = Number(swSel.value);
                const cs = coreSwitches.find(s => Number(s.id) === csId);
                const portIdx = portSel.selectedIndex;
                if (!csId || portIdx <= 0) {
                    preview.style.display = 'none';
                    return;
                }
                const lbl = portSel.options[portIdx].dataset.label || '';
                preview.style.display = '';
                previewText.textContent = cs.name + ' | ' + lbl;
                // Write JSON to connection info field
                const vcJson = JSON.stringify({
                    type: 'virtual_core',
                    core_switch_id: csId,
                    core_switch_name: cs.name,
                    core_port: Number(portSel.value),
                    core_port_label: lbl
                });
                connInfoEl.value = vcJson;
            }

            // Clone to remove old listeners
            const newSwSel = swSel.cloneNode(true);
            swSel.parentNode.replaceChild(newSwSel, swSel);
            const newPortSel = portSel.cloneNode(true);
            portSel.parentNode.replaceChild(newPortSel, portSel);
            document.getElementById('core-switch-select').addEventListener('change', updateCorePorts);
            document.getElementById('core-switch-port-select').addEventListener('change', updateCorePreview);

            // Pre-fill if existing connection is virtual_core
            if (existingConnection && existingConnection.connection_info_preserved) {
                try {
                    const parsed = JSON.parse(existingConnection.connection_info_preserved);
                    if (parsed && parsed.type === 'virtual_core' && parsed.core_switch_id) {
                        setTimeout(() => {
                            const s2 = document.getElementById('core-switch-select');
                            if (s2) {
                                s2.value = parsed.core_switch_id;
                                s2.dispatchEvent(new Event('change'));
                                setTimeout(() => {
                                    const p2 = document.getElementById('core-switch-port-select');
                                    if (p2) { p2.value = parsed.core_port; p2.dispatchEvent(new Event('change')); }
                                }, 80);
                            }
                        }, 50);
                    }
                } catch(e) {}
            }
        }

        // Device Import Lookup - MAC adresine göre cihaz bilgilerini otomatik doldur
        function setupDeviceImportLookup() {
            const macInput = document.getElementById('port-mac');
            
            if (!macInput) return;
            
            // Önceki event listener'ları temizle
            const newMacInput = macInput.cloneNode(true);
            macInput.parentNode.replaceChild(newMacInput, macInput);
            
            // Yeni event listener ekle
            document.getElementById('port-mac').addEventListener('blur', function() {
                const mac = this.value.trim();
                if (mac && mac.length >= 12) {
                    lookupDeviceByMac(mac);
                }
            });
        }

        // MAC adresine göre Device Import registry'den cihaz bilgilerini al
        // Auto-save helper function
        function autoFillField(input, value) {
            if (value && (!input.value || input.value.trim() === '')) {
                input.value = value;
                // Görsel feedback
                input.style.backgroundColor = '#dcfce7'; // Açık yeşil
                setTimeout(() => {
                    input.style.backgroundColor = '';
                }, 2000);
                return true; // Field was filled
            }
            return false; // Field was not filled
        }

        // Auto-save port connection after Device Import lookup
        async function autoSavePortConnection() {
            try {
                const portId = document.getElementById('port-id').value;
                const mac = document.getElementById('port-mac').value;
                
                // Only save if we have essentials
                if (!portId || !mac) {
                    console.log('Auto-save skipped: missing required fields');
                    return;
                }
                
                const formData = new FormData();
                formData.append('port_id', portId);
                formData.append('switch_id', document.getElementById('port-switch-id').value);
                formData.append('port_number', document.getElementById('port-number').value);
                formData.append('mac', mac);
                formData.append('ip', document.getElementById('port-ip').value || '');
                formData.append('user_name', document.getElementById('port-user').value || '');
                formData.append('location', document.getElementById('port-location').value || '');
                formData.append('department', document.getElementById('port-department').value || '');
                formData.append('notes', document.getElementById('port-notes').value || '');
                formData.append('connection_type', document.getElementById('port-connection-type').value || '');
                formData.append('connection_info', document.getElementById('port-connection-info').value || '');
                
                const response = await fetch('api/getData.php?action=updatePortConnection', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showToast('Port bağlantısı otomatik kaydedildi (Device Import)', 'success');
                    closePortModal();
                    // Refresh current page to show updated data
                    loadCurrentPage();
                } else {
                    console.error('Auto-save failed:', result.error);
                }
            } catch (error) {
                console.error('Auto-save exception:', error);
                // Silent failure - modal stays open, user can manually save
            }
        }

        async function lookupDeviceByMac(mac) {
            if (!mac || mac.trim() === '') return;
            
            try {
                const response = await fetch(`api/device_import_api.php?action=get&mac=${encodeURIComponent(mac)}`);
                const data = await response.json();
                
                if (data.success && data.device) {
                    const device = data.device;
                    const ipInput = document.getElementById('port-ip');
                    const connectionInfoInput = document.getElementById('port-connection-info');
                    
                    // Check if elements exist before proceeding
                    if (!ipInput || !connectionInfoInput) {
                        console.error('Port form elements not found');
                        return;
                    }
                    
                    // Use helper function to fill and track if fields were filled
                    const ipFilled = autoFillField(ipInput, device.ip_address);
                    const infoFilled = autoFillField(connectionInfoInput, device.device_name);
                    
                    // Auto-save if we're in edit mode (has port-id) and fields were filled
                    const portIdElement = document.getElementById('port-id');
                    const isEditMode = portIdElement && portIdElement.value !== '';
                    if (isEditMode && (ipFilled || infoFilled)) {
                        // Immediately save to database
                        await autoSavePortConnection();
                    } else if (ipFilled || infoFilled) {
                        // Only show toast if not auto-saving (new connection)
                        showToast('Device Import kaydı bulundu ve bilgiler dolduruldu', 'success', 3000);
                    }
                } else {
                    // Kayıt bulunamadı - sessizce devam et, hata gösterme
                    console.log('Device Import kaydı bulunamadı:', mac);
                }
            } catch (error) {
                console.error('Device Import lookup hatası:', error);
                // Sessizce devam et, kullanıcıya hata gösterme
            }
        }

        // Rack'teki panelleri filtrele ve yükle
        function loadPanelsForRack(rackId, panelType, isFiberPort) {
            const panelSelect = document.getElementById('patch-panel-select');
            const portInput = document.getElementById('patch-port-number');
            
            panelSelect.innerHTML = '<option value="">Panel Seçin</option>';
            panelSelect.disabled = true;
            portInput.disabled = true;
            
            if (!rackId || !panelType) return;
            
            // Bu rack'teki panelleri filtrele
            let panels = [];
            if (panelType === 'patch') {
                panels = patchPanels.filter(p => p.rack_id == rackId);
            } else if (panelType === 'fiber') {
                panels = fiberPanels.filter(p => p.rack_id == rackId);
            }
            
            if (panels.length === 0) {
                panelSelect.innerHTML = '<option value="">Bu rack\'te ' + (panelType === 'patch' ? 'patch' : 'fiber') + ' panel yok</option>';
                return;
            }
            
            // Panelleri listele
            panels.forEach(panel => {
                const option = document.createElement('option');
                option.value = panel.id;
                const portCount = panelType === 'patch' ? panel.total_ports : panel.total_fibers;
                option.textContent = `Panel ${panel.panel_letter} (${portCount} ${panelType === 'patch' ? 'port' : 'fiber'})`;
                option.dataset.letter = panel.panel_letter;
                option.dataset.rackName = panel.rack_name;
                option.dataset.maxPorts = portCount;
                panelSelect.appendChild(option);
            });
            
            panelSelect.disabled = false;
            
            // Panel seçim eventi
            panelSelect.addEventListener('change', function() {
                portInput.disabled = !this.value;
                if (this.value) {
                    const selectedOption = this.options[this.selectedIndex];
                    portInput.max = selectedOption.dataset.maxPorts;
                }
                updatePanelPreview();
            });
            
            // Port numarası değişim eventi
            portInput.addEventListener('input', updatePanelPreview);
        }

        // Panel bağlantı önizlemesi
        function updatePanelPreview() {
            const panelTypeSelect = document.getElementById('panel-type-select');
            const panelSelect = document.getElementById('patch-panel-select');
            const portInput = document.getElementById('patch-port-number');
            const display = document.getElementById('patch-display');
            
            if (panelSelect.value && portInput.value) {
                const selectedOption = panelSelect.options[panelSelect.selectedIndex];
                const panelLetter = selectedOption.dataset.letter;
                const rackName = selectedOption.dataset.rackName;
                const panelType = panelTypeSelect.value;
                
                display.innerHTML = `
                    <i class="fas fa-${panelType === 'fiber' ? 'satellite-dish' : 'th-large'}"></i>
                    ${rackName}-${panelLetter}${portInput.value}
                    <span style="color: var(--text-light); font-size: 0.9rem;">(${panelType === 'fiber' ? 'Fiber' : 'Patch'} Panel)</span>
                `;
            } else {
                display.textContent = '';
            }
        }

        // ============================================
        // DATA MANAGEMENT FONKSİYONLARI - GÜNCELLENDİ
        // ============================================

        async function loadData() {
            try {
                showLoading();
                
                const response = await fetch('api/getData.php');
                if (!response.ok) {
                    throw new Error(`HTTP hatası! Durum: ${response.status}`);
                }
                
                const data = await response.json();
                
                if (!data.success) {
                    throw new Error(data.error || 'Veri yükleme başarısız');
                }
                
                switches = data.switches || [];
                racks = data.racks || [];
                portConnections = data.ports || {};
                patchPanels = data.patch_panels || [];
                patchPorts = data.patch_ports || {};
                fiberPanels = data.fiber_panels || [];
                fiberPorts = data.fiber_ports || {};
                rackDevices = data.rack_devices || [];
                hubSwPortConnections = data.hub_sw_port_connections || [];
                
                console.log('Veriler yüklendi:', {
                    switchCount: switches.length,
                    rackCount: racks.length,
                    patchPanelCount: patchPanels.length,
                    patchPortCount: Object.keys(patchPorts).length,
                    fiberPanelCount: fiberPanels.length,
                    fiberPortCount: Object.keys(fiberPorts).length,
                    rackDeviceCount: rackDevices.length
                });
                
                updateStats();
                updateSidebarStats();
                loadDashboard();
                
            } catch (error) {
                console.error('Veri yükleme hatası:', error);
                showToast('Veriler yüklenemedi: ' + error.message, 'error');
                throw error;
            } finally {
                hideLoading();
            }
        }

        // CRUD Operations
        async function addSwitch(switchData) {
            try {
                const response = await fetch('actions/saveSwitch.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(switchData)
                });
                
                const result = await response.json();
                if (result.success) {
                    await loadData();
                    updateStats();
                    showToast('Switch başarıyla eklendi', 'success');
                    return true;
                } else {
                    throw new Error(result.error || 'Switch kaydedilemedi');
                }
            } catch (error) {
                console.error('Switch ekleme hatası:', error);
                showToast('Switch eklenemedi: ' + error.message, 'error');
                return false;
            }
        }

        async function updateSwitch(switchData) {
            try {
                switchData.id = parseInt(switchData.id);
                const response = await fetch('actions/saveSwitch.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(switchData)
                });
                
                const result = await response.json();
                if (result.success) {
                    await loadData();
                    updateStats();
                    if (selectedSwitch && selectedSwitch.id == switchData.id) {
                        const updatedSwitch = switches.find(s => s.id == switchData.id);
                        if (updatedSwitch) showSwitchDetail(updatedSwitch);
                    }
                    showToast('Switch başarıyla güncellendi', 'success');
                    return true;
                } else {
                    throw new Error(result.error || 'Switch güncellenemedi');
                }
            } catch (error) {
                console.error('Switch güncelleme hatası:', error);
                showToast('Switch güncellenemedi: ' + error.message, 'error');
                return false;
            }
        }

        async function deleteSwitch(switchId) {
            if (!confirm('Switch silinecek, emin misiniz?')) return;
            
            try {
                const response = await fetch(`api/delete.php?type=switch&id=${switchId}`);
                const result = await response.json();
                
                if (result.status === 'deleted') {
                    await loadData();
                    updateStats();
                    hideDetailPanel();
                    showToast('Switch silindi', 'success');
                } else {
                    throw new Error(result.message || 'Switch silinemedi');
                }
            } catch (error) {
                console.error('Switch silme hatası:', error);
                showToast('Switch silinemedi: ' + error.message, 'error');
            }
        }

        async function addRack(rackData) {
            try {
                const response = await fetch('actions/saveRack.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(rackData)
                });
                
                const result = await response.json();
                if (result.success) {
                    await loadData();
                    updateStats();
                    showToast('Rack başarıyla eklendi', 'success');
                    return true;
                } else {
                    throw new Error(result.error || 'Rack kaydedilemedi');
                }
            } catch (error) {
                console.error('Rack ekleme hatası:', error);
                showToast('Rack eklenemedi: ' + error.message, 'error');
                return false;
            }
        }

        async function updateRack(rackData) {
            try {
                const response = await fetch('actions/saveRack.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(rackData)
                });
                
                const result = await response.json();
                if (result.success) {
                    await loadData();
                    updateStats();
                    showToast('Rack başarıyla güncellendi', 'success');
                    return true;
                } else {
                    throw new Error(result.error || 'Rack güncellenemedi');
                }
            } catch (error) {
                console.error('Rack güncelleme hatası:', error);
                showToast('Rack güncellenemedi: ' + error.message, 'error');
                return false;
            }
        }

        async function deleteRack(rackId) {
            if (!confirm('Rack ve içindeki tüm switch\'ler silinecek, emin misiniz?')) return;
            
            try {
                const response = await fetch(`api/delete.php?type=rack&id=${rackId}`);
                const result = await response.json();
                
                if (result.status === 'deleted') {
                    await loadData();
                    updateStats();
                    showToast('Rack silindi', 'success');
                } else {
                    throw new Error(result.message || 'Rack silinemedi');
                }
            } catch (error) {
                console.error('Rack silme hatası:', error);
                showToast('Rack silinemedi: ' + error.message, 'error');
            }
        }

        // Port form submit
        document.getElementById('port-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const switchId = document.getElementById('port-switch-id').value;
            const portNo = document.getElementById('port-number').value;
            const type = document.getElementById('port-type').value;
            const device = document.getElementById('port-device').value;
            const ip = document.getElementById('port-ip').value;
            const mac = document.getElementById('port-mac').value;
            
            // ÖNEMLİ: CONNECTION INFO HER ZAMAN ALINIR
            const connectionInfo = document.getElementById('port-connection-info').value;
            
            // Panel bilgileri (opsiyonel)
            const panelType = document.getElementById('panel-type-select').value;
            const panelId = document.getElementById('patch-panel-select').value;
            const panelPort = document.getElementById('patch-port-number').value;
            
            const formData = {
                switchId: parseInt(switchId),
                port: parseInt(portNo),
                type: type,
                device: device,
                ip: ip,
                mac: mac,
                connectionInfo: connectionInfo, // HER ZAMAN GÖNDERİLİR
                panelId: panelId ? parseInt(panelId) : null,
                panelPort: panelPort ? parseInt(panelPort) : null,
                panelType: panelType || null
            };
            
            try {
                showLoading();
                
                const response = await fetch('actions/savePortWithPanel.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(formData)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showToast('Port bağlantısı kaydedildi' + (panelId ? ' ve panel senkronize edildi' : ''), 'success');
                    document.getElementById('port-modal').classList.remove('active');
                    await loadData();
                    
                    // Switch detail'i yenile
                    if (selectedSwitch && selectedSwitch.id == switchId) {
                        const sw = switches.find(s => s.id == switchId);
                        if (sw) showSwitchDetail(sw);
                    }
                } else {
                    throw new Error(result.error || 'Kayıt başarısız');
                }
            } catch (error) {
                console.error('Port kaydetme hatası:', error);
                showToast('Port kaydedilemedi: ' + error.message, 'error');
            } finally {
                hideLoading();
            }
        });

        async function savePort(formData) {
            try {
                // IP ve MAC yoksa port BOŞ say
                if ((!formData.ip || formData.ip.trim() === '') && 
                    (!formData.mac || formData.mac.trim() === '')) {
                    formData.type = 'BOŞ';
                    formData.device = '';
                }
                
                const response = await fetch('actions/updatePort.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });
                
                const result = await response.json();
                if (result.status === 'ok') {
                    await loadData();
                    updateStats();
                    if (selectedSwitch && selectedSwitch.id == formData.switchId) {
                        const sw = switches.find(s => s.id == formData.switchId);
                        if (sw) showSwitchDetail(sw);
                    }
                    showToast(result.message, 'success');
                } else {
                    throw new Error(result.message || 'Port güncellenemedi');
                }
            } catch (error) {
                console.error('Port kaydetme hatası:', error);
                showToast('Port güncellenemedi: ' + error.message, 'error');
            }
        }

        async function phpVlanSync() {
            try {
                showLoading();
                const resp = await fetch('api/snmp_data_api.php?action=php_vlan_sync');
                const res  = await resp.json();
                if (res.success) {
                    await loadData();
                    if (selectedSwitch) showSwitchDetail(selectedSwitch);
                    const msg = `VLAN güncellendi: ${res.updated_ports} port` +
                        (res.errors && res.errors.length ? ' (uyarılar: ' + res.errors.join('; ') + ')' : '');
                    showToast(msg, res.errors && res.errors.length ? 'warning' : 'success');
                } else {
                    showToast('VLAN güncelleme hatası: ' + (res.error || 'Bilinmeyen hata'), 'error');
                }
            } catch (e) {
                showToast('VLAN güncelleme hatası: ' + e.message, 'error');
            } finally {
                hideLoading();
            }
        }

        // Auto PHP VLAN sync – runs silently every 120 seconds.
        // PHP SNMP is the reliable source for VLAN data on CBS350.
        // This ensures VLAN changes on the switch config are reflected
        // in the UI within 2 minutes without any manual button press.
        async function phpVlanSyncSilent() {
            try {
                const resp = await fetch('api/snmp_data_api.php?action=php_vlan_sync');
                const res  = await resp.json();
                if (res.success && res.updated_ports > 0) {
                    await loadData();
                    if (selectedSwitch) showSwitchDetail(selectedSwitch);
                }
            } catch (e) {
                // Silently ignore errors in background sync
            }
        }
        // Auto-sync disabled: php_snmp.dll causes Apache heap-corruption crashes on
        // Windows (XAMPP) when SNMP walks run inside the Apache worker process.
        // VLAN data is kept up-to-date by the Python polling worker; manual sync is
        // still available via the "VLAN Sync" button in the UI.
        // setInterval(phpVlanSyncSilent, 120000);

        async function resetAllPorts(switchId) {
            if (!confirm('Bu switch\'teki TÜM port bağlantılarını boşa çekmek istediğinize emin misiniz?')) return;
            
            try {
                showLoading();
                
                const response = await fetch('actions/updatePort.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        switchId: switchId,
                        action: 'reset_all'
                    })
                });
                
                const result = await response.json();
                if (result.status === 'ok') {
                    await loadData();
                    updateStats();
                    if (selectedSwitch && selectedSwitch.id == switchId) {
                        const updatedSwitch = switches.find(s => s.id == switchId);
                        if (updatedSwitch) showSwitchDetail(updatedSwitch);
                    }
                    showToast('Tüm portlar başarıyla boşa çekildi', 'success');
                } else {
                    throw new Error(result.message || 'Portlar sıfırlanamadı');
                }
            } catch (error) {
                console.error('Port sıfırlama hatası:', error);
                showToast('Portlar sıfırlanamadı: ' + error.message, 'error');
            } finally {
                hideLoading();
            }
        }

        // UI Functions
        function updateStats() {
            try {
                const totalSwitches = switches.length;
                const onlineSwitches = switches.filter(s => s.status === 'online').length;
                const totalRacks = racks.length;
                const totalPatchPanels = patchPanels.length;
                const totalFiberPanels = fiberPanels.length;
                
                // Total ports = sum of each switch's port capacity
                const totalPorts = switches.reduce((sum, sw) => sum + (parseInt(sw.ports) || 0), 0);

                let activePorts = 0;
                
                Object.values(portConnections).forEach(connections => {
                    activePorts += connections.filter(c => c.is_active && !c.is_down).length;
                });
                
                // Elementleri güncelle
                document.getElementById('stat-total-switches').textContent = totalSwitches;
                document.getElementById('stat-total-racks').textContent = totalRacks;
                document.getElementById('stat-total-panels').textContent = totalPatchPanels + totalFiberPanels;
                document.getElementById('stat-active-ports').textContent = activePorts;
                document.getElementById('stat-total-ports-label').textContent = totalPorts;
                document.getElementById('stat-active-ports-label').textContent = activePorts;
                
            } catch (error) {
                console.error('updateStats hatası:', error);
            }
        }

        function updateSidebarStats() {
            try {
                const totalSwitches = switches.length;
                const totalPanels = patchPanels.length + fiberPanels.length;
                
                let activePorts = 0;
                
                Object.values(portConnections).forEach(connections => {
                    activePorts += connections.filter(c => 
                        c.device && c.device.trim() !== '' && 
                        c.type && c.type !== 'BOŞ'
                    ).length;
                });
                
                // Sidebar statistics removed - no longer updating
                // Previously updated: sidebar-total-switches, sidebar-active-ports, sidebar-total-panels, sidebar-last-backup
                
            } catch (error) {
                console.error('updateSidebarStats hatası:', error);
            }
        }

        function updateBackupIndicator() {
            // Backup indicator removed; backups are managed from admin.php
        }

        function loadDashboard() {
            const container = document.getElementById('dashboard-racks');
            if (!container) return;
            
            container.innerHTML = '';
            
            racks.forEach(rack => {
                const rackSwitches = switches.filter(s => s.rack_id === rack.id);
                const rackPatchPanels = patchPanels.filter(p => p.rack_id === rack.id);
                const rackFiberPanels = fiberPanels.filter(fp => fp.rack_id === rack.id);
                const rackHubSwitches = (rackDevices || []).filter(d => d.rack_id == rack.id && d.device_type === 'hub_sw');

                const totalSlots = rack.slots || 42;
                const filled = rackSwitches.length + rackPatchPanels.length + rackFiberPanels.length + rackHubSwitches.length;
                const filledPct = Math.min(100, Math.round(filled / totalSlots * 100));
                const usageColor = filledPct > 80 ? '#ef4444' : filledPct > 50 ? '#f59e0b' : '#10b981';

                // Slot dot strip – shows every slot up to totalSlots (capped at 52 for display)
                const slotDots = Array.from({length: Math.min(totalSlots, 52)}, (_, i) => {
                    const sn = i + 1;
                    const hasSw  = rackSwitches.find(s => s.position_in_rack == sn);
                    const hasPp  = rackPatchPanels.find(p => p.position_in_rack == sn);
                    const hasFp  = rackFiberPanels.find(f => f.position_in_rack == sn);
                    const hasRd  = rackHubSwitches.find(d => d.position_in_rack == sn);
                    const cls = hasSw ? 'sw-dot' : hasPp ? 'pp-dot' : hasFp ? 'fp-dot' : hasRd ? 'sw-dot' : 'em-dot';
                    return `<span class="slot-dot ${cls}"></span>`;
                }).join('');

                const rackCard = document.createElement('div');
                rackCard.className = 'rack-card dashboard-rack';
                rackCard.innerHTML = `
                    <div class="rack-summary">
                        <div class="rack-slot-strip">${slotDots}</div>
                        <div class="rack-stat-badges">
                            ${rackSwitches.length   > 0 ? `<span class="rstat sw"><i class="fas fa-network-wired"></i> ${rackSwitches.length} SW</span>` : ''}
                            ${rackPatchPanels.length > 0 ? `<span class="rstat pp"><i class="fas fa-th"></i> ${rackPatchPanels.length} Panel</span>` : ''}
                            ${rackFiberPanels.length > 0 ? `<span class="rstat fp"><i class="fas fa-link"></i> ${rackFiberPanels.length} Fiber</span>` : ''}
                            ${rackHubSwitches.length > 0 ? `<span class="rstat sw" style="opacity:0.75;"><i class="fas fa-sitemap"></i> ${rackHubSwitches.length} Hub SW</span>` : ''}
                            <span class="rstat em">${totalSlots - filled} Boş</span>
                        </div>
                        <div class="rack-usage-bar">
                            <div class="rack-usage-fill" style="width:${filledPct}%;background:${usageColor};"></div>
                        </div>
                    </div>
                    <div class="rack-header">
                        <div class="rack-title">${rack.name}</div>
                        <div class="rack-switches">${filled}/${totalSlots} Slot</div>
                    </div>
                    <div class="rack-info">
                        <div class="rack-location">
                            <i class="fas fa-map-marker-alt"></i>
                            <span>${rack.location}</span>
                        </div>
                        <div>${totalSlots} Slot</div>
                    </div>
                    ${(rackSwitches.length > 0 || rackHubSwitches.length > 0) ? `
                        <div class="rack-switch-preview">
                            ${rackSwitches.map(sw => {
                                const temp  = sw.snmp_temperature_c != null ? parseFloat(sw.snmp_temperature_c) : null;
                                const cpu   = sw.snmp_cpu_1min      != null ? parseFloat(sw.snmp_cpu_1min)      : null;
                                const fan   = (sw.snmp_fan_status && sw.snmp_fan_status !== 'N/A') ? sw.snmp_fan_status : null;
                                const tColor = temp !== null ? (temp >= 70 ? '#ef4444' : temp >= 55 ? '#f59e0b' : '#10b981') : '#475569';
                                const cColor = cpu  !== null ? (cpu  >= 80 ? '#ef4444' : cpu  >= 60 ? '#f59e0b' : '#94a3b8') : '#475569';
                                const fColor = fan  !== null ? (fan === 'OK' ? '#10b981' : fan === 'WARNING' ? '#f59e0b' : '#ef4444') : '#475569';
                                const fIcon  = fan  !== null ? (fan === 'OK' ? 'fa-fan' : 'fa-exclamation-triangle') : 'fa-fan';
                                const pills = `
                                    <span style="display:flex;gap:4px;align-items:center;flex-wrap:nowrap;margin-top:2px;">
                                        <span style="font-size:9px;color:${tColor};font-weight:700;" title="Sıcaklık"><i class="fas fa-thermometer-half" style="margin-right:1px;"></i>${temp !== null ? temp + '°C' : '—'}</span>
                                        <span style="color:#334155;">·</span>
                                        <span style="font-size:9px;color:${cColor};font-weight:700;" title="CPU"><i class="fas fa-microchip" style="margin-right:1px;"></i>${cpu !== null ? cpu + '%' : '—'}</span>
                                        <span style="color:#334155;">·</span>
                                        <span style="font-size:9px;color:${fColor};font-weight:700;" title="Fan"><i class="fas ${fIcon}" style="margin-right:1px;"></i>${fan !== null ? fan : '—'}</span>
                                    </span>`;
                                return `<div class="preview-switch" style="flex-direction:column;align-items:flex-start;padding:4px 8px;"><span style="font-size:0.75rem;font-weight:600;">${sw.name}</span>${pills}</div>`;
                            }).join('')}
                            ${rackHubSwitches.map(d =>
                                `<div class="preview-switch" style="opacity:0.75;"><i class="fas fa-sitemap" style="margin-right:3px;font-size:0.7rem;"></i>${d.name}</div>`
                            ).join('')}
                        </div>
                    ` : ''}
                `;
                
                rackCard.addEventListener('click', () => {
                    showRackDetail(rack);
                });
                
                container.appendChild(rackCard);
            });
        }

        // ============================================
        // PANEL DETAY FONKSİYONLARI
        // ============================================

   // ============================================
// PANEL DETAY FONKSİYONLARI - GÜNCELLENDİ
// ============================================

window.showPanelDetail = function(panelId, panelType) {
    const modal = document.getElementById('panel-detail-modal');
    const content = document.getElementById('panel-detail-content');
    
    let panel, ports;
    
    if (panelType === 'patch') {
        panel = patchPanels.find(p => p.id == panelId);
        ports = patchPorts[panelId] || [];
    } else if (panelType === 'fiber') {
        panel = fiberPanels.find(p => p.id == panelId);
        ports = [];
    }
    
    if (!panel) {
        showToast('Panel bulunamadı', 'error');
        return;
    }
    
    const rack = racks.find(r => r.id == panel.rack_id);
    
    let html = `
        <div style="margin-bottom: 30px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <div>
                    <h3 style="color: var(--text); margin-bottom: 5px;">
                        ${panelType === 'patch' ? 'Patch' : 'Fiber'} Panel ${panel.panel_letter}
                    </h3>
                    <div style="color: var(--text-light);">
                        <i class="fas fa-server"></i> ${rack ? rack.name : 'Bilinmeyen Rack'}
                        ${panel.position_in_rack ? ` • Slot ${panel.position_in_rack}` : ''}
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 2rem; color: var(--primary); font-weight: bold;">
                        ${panelType === 'patch' ? panel.total_ports : panel.total_fibers}
                    </div>
                    <div style="color: var(--text-light); font-size: 0.9rem;">
                        ${panelType === 'patch' ? 'Port' : 'Fiber'}
                    </div>
                </div>
            </div>
            
            ${panel.description ? `
                <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px; margin-bottom: 20px;">
                    <strong style="color: var(--primary);">Açıklama:</strong><br>
                    ${panel.description}
                </div>
            ` : ''}
        </div>
    `;
    
    // === PATCH PANEL KODU - GÜNCELLENDİ ===
    if (panelType === 'patch' && ports.length > 0) {
        const activeCount = ports.filter(p => p.status === 'active').length;
        
        html += `
            <div style="margin-bottom: 20px;">
                <h4 style="color: var(--primary); margin-bottom: 15px;">
                    Port Durumu (${activeCount}/${ports.length} Aktif)
                </h4>
                
                <div class="ports-grid" style="grid-template-columns: repeat(auto-fill, minmax(80px, 1fr));">
        `;
        
        ports.forEach(port => {
            const isActive = port.status === 'active';
            let connectionDisplay = '';
            
            // Bağlantı bilgisini düzgün formatla
            if (isActive) {
                if (port.connected_switch_name && port.connected_switch_port) {
                    connectionDisplay = `${port.connected_switch_name} : Port ${port.connected_switch_port}`;
                } else if (port.connected_switch_id && port.connected_switch_port) {
                    // Switch adını bul
                    const connectedSwitch = switches.find(s => Number(s.id) === Number(port.connected_switch_id));
                    if (connectedSwitch) {
                        connectionDisplay = `${connectedSwitch.name} : Port ${port.connected_switch_port}`;
                    } else {
                        connectionDisplay = `SW${port.connected_switch_id} : Port ${port.connected_switch_port}`;
                    }
                } else if (port.connection_details) {
                    // Parse connection_details JSON for rack_device / free-text device
                    try {
                        const cd = typeof port.connection_details === 'string'
                            ? JSON.parse(port.connection_details) : port.connection_details;
                        if (cd && cd.device_name) {
                            connectionDisplay = cd.device_name;
                            if (cd.rack_device_port) {
                                connectionDisplay += ` : Port ${cd.rack_device_port}`;
                            }
                        }
                    } catch(e) { /* ignore */ }
                } else if (port.connected_to) {
                    connectionDisplay = port.connected_to;
                }
            }
            
            html += `
                <div class="port-item ${isActive ? 'connected' : ''}" 
                     style="cursor: pointer;"
                     onclick="editPatchPort(${panelId}, ${port.port_number})"
                     title="${isActive ? `Bağlı: ${escapeHtml(connectionDisplay)}` : 'Boş port'}">
                    <div class="port-number">${port.port_number}</div>
                    <div class="port-type ${isActive ? 'active' : 'empty'}" 
                         style="background: ${isActive ? '#10b981' : '#64748b'};">
                        ${isActive ? 'AKTİF' : 'BOŞ'}
                    </div>
                    
                    ${connectionDisplay ? `
                        <div class="port-device" style="font-size: 0.7rem; margin-top: 8px; color: var(--primary); font-weight: bold;">
                            <i class="fas fa-link"></i> ${escapeHtml(connectionDisplay.length > 15 ? connectionDisplay.substring(0, 15) + '...' : connectionDisplay)}
                        </div>
                    ` : ''}
                    
                    ${port.device ? `
                        <div class="port-device" style="font-size: 0.65rem; margin-top: 3px; color: var(--text-light);">
                            ${escapeHtml(port.device.length > 12 ? port.device.substring(0, 12) + '...' : port.device)}
                        </div>
                    ` : ''}
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
    }
    // === PATCH PANEL KODU SONU ===
    
    // === FIBER PANEL KODU - GÜNCELLENDİ (KÖPRÜ BAĞLANTILARI İLE) ===
else if (panelType === 'fiber') {
    const panelPorts = fiberPorts[panelId] || [];
    
    html += `
        <div style="margin-bottom: 20px;">
            <h4 style="color: var(--primary); margin-bottom: 15px;">Fiber Port Durumu (${panel.total_fibers})</h4>
            <div class="ports-grid" style="grid-template-columns: repeat(auto-fill, minmax(90px, 1fr));">
    `;
    
    if (panel.total_fibers && panel.total_fibers > 0) {
        for (let i = 1; i <= panel.total_fibers; i++) {
            const p = panelPorts.find(x => parseInt(x.port_number) === i);
            const isActive = p && (p.status === 'active' || 
                (p.connected_switch_id && p.connected_switch_port) || 
                (p.connected_fiber_panel_id && p.connected_fiber_panel_port));
            
            let connectionDisplay = '';
            let connectionType = '';
            
            if (isActive && p) {
                // 1. Switch bağlantısı kontrolü
                if (p.connected_switch_name && p.connected_switch_port) {
                    connectionDisplay = `${p.connected_switch_name} : Port ${p.connected_switch_port}`;
                    connectionType = 'switch';
                } else if (p.connected_switch_id && p.connected_switch_port) {
                    const connectedSwitch = switches.find(s => Number(s.id) === Number(p.connected_switch_id));
                    if (connectedSwitch) {
                        connectionDisplay = `${connectedSwitch.name} : Port ${p.connected_switch_port}`;
                        connectionType = 'switch';
                    } else {
                        connectionDisplay = `SW${p.connected_switch_id} : Port ${p.connected_switch_port}`;
                        connectionType = 'switch';
                    }
                } 
                // 2. Fiber panel bağlantısı (KÖPRÜ) kontrolü
                else if (p.connected_fiber_panel_id && p.connected_fiber_panel_port) {
                    const peerPanelId = p.connected_fiber_panel_id;
                    const peerPort = p.connected_fiber_panel_port;
                    
                    // Bağlı olduğu fiber panel bilgilerini bul
                    const peerPanel = fiberPanels.find(fp => Number(fp.id) === Number(peerPanelId));
                    
                    if (peerPanel) {
                        const peerRack = racks.find(r => Number(r.id) === Number(peerPanel.rack_id));
                        connectionDisplay = `Panel ${peerPanel.panel_letter} : Port ${peerPort}`;
                        if (peerRack) {
                            connectionDisplay += ` (${peerRack.name})`;
                        }
                        connectionType = 'fiber_bridge';
                    } else {
                        connectionDisplay = `Panel ${peerPanelId} : Port ${peerPort}`;
                        connectionType = 'fiber_bridge';
                    }
                } 
                // 3. Eski bağlantı formatı
                else if (p.connected_to) {
                    connectionDisplay = p.connected_to;
                    connectionType = 'other';
                }
            }
            
            // Bağlantı tipine göre icon belirle
            let connectionIcon = 'fa-link';
            if (connectionType === 'switch') {
                connectionIcon = 'fa-network-wired';
            } else if (connectionType === 'fiber_bridge') {
                connectionIcon = 'fa-satellite-dish';
            }
            
            html += `
                <div class="port-item ${isActive ? 'connected' : ''}" 
                     style="cursor: pointer; position: relative;"
                     onclick="editFiberPort(${panelId}, ${i}, ${panel.rack_id})"
                     title="${isActive ? `Bağlı: ${escapeHtml(connectionDisplay)}` : 'Boş fiber port'}">
                    <div class="port-number">${i}</div>
                    <div class="port-type ${isActive ? 'fiber' : 'boş'}" 
                         style="background: ${isActive ? 
                             (connectionType === 'fiber_bridge' ? '#f59e0b' : '#8b5cf6') : 
                             '#64748b'};">
                        ${isActive ? 'AKTİF' : 'BOŞ'}
                    </div>
                    
                    ${connectionDisplay ? `
                        <div class="port-device" style="font-size: 0.65rem; margin-top: 8px; color: ${connectionType === 'fiber_bridge' ? '#f59e0b' : 'var(--primary)'}; font-weight: bold;">
                            <i class="fas ${connectionIcon}"></i> ${escapeHtml(connectionDisplay.length > 18 ? connectionDisplay.substring(0, 18) + '...' : connectionDisplay)}
                        </div>
                    ` : ''}
                    
                    ${p && p.device ? `
                        <div class="port-device" style="font-size: 0.6rem; margin-top: 3px; color: var(--text-light);">
                            ${escapeHtml(p.device.length > 15 ? p.device.substring(0, 15) + '...' : p.device)}
                        </div>
                    ` : ''}
                    
                    ${connectionType === 'fiber_bridge' ? `
                        <div style="position: absolute; top: 2px; right: 2px; font-size: 0.6rem; color: #f59e0b;">
                            <i class="fas fa-exchange-alt" title="Köprü Bağlantısı"></i>
                        </div>
                    ` : ''}
                </div>
            `;
        }
    } else {
        html += `<div style="grid-column: 1/-1; text-align: center; color: var(--text-light);">Bu panel için port verisi yok</div>`;
    }
    
    // KÖPRÜ BAĞLANTILARI ÖZETİ
    const bridgeConnections = panelPorts.filter(p => p.connected_fiber_panel_id && p.connected_fiber_panel_port);
    if (bridgeConnections.length > 0) {
        html += `
            </div>
            
            <div style="margin-top: 25px; background: rgba(245, 158, 11, 0.1); border-left: 4px solid #f59e0b; border-radius: 8px; padding: 15px;">
                <h5 style="color: #f59e0b; margin-bottom: 10px;">
                    <i class="fas fa-exchange-alt"></i> Köprü Bağlantıları (${bridgeConnections.length})
                </h5>
                <div style="font-size: 0.85rem;">
        `;
        
        bridgeConnections.forEach((conn, index) => {
            const peerPanel = fiberPanels.find(fp => Number(fp.id) === Number(conn.connected_fiber_panel_id));
            const peerRack = peerPanel ? racks.find(r => Number(r.id) === Number(peerPanel.rack_id)) : null;
            
            html += `
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px; padding: 5px; background: rgba(245, 158, 11, 0.05); border-radius: 5px;">
                    <span style="color: var(--text);">
                        Port ${conn.port_number} 
                        <i class="fas fa-arrow-right" style="margin: 0 5px; color: #f59e0b; font-size: 0.8rem;"></i>
                        Panel ${peerPanel ? peerPanel.panel_letter : conn.connected_fiber_panel_id}:${conn.connected_fiber_panel_port}
                        ${peerRack ? ` (${peerRack.name})` : ''}
                    </span>
                    <div style="display:flex; gap:4px;">
                        <button class="btn btn-sm" style="padding: 2px 8px; font-size: 0.7rem; background: rgba(245, 158, 11, 0.2);" 
                                onclick="editFiberPort(${panelId}, ${conn.port_number}, ${panel.rack_id})">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-sm" style="padding: 2px 8px; font-size: 0.7rem; background: rgba(239, 68, 68, 0.2); color: #ef4444;" 
                                onclick="removeFiberBridgeConnection(${panelId}, ${conn.port_number})">
                            <i class="fas fa-unlink"></i>
                        </button>
                    </div>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
    } else {
        html += `</div>`;
    }
}
// === FIBER PANEL KODU SONU ===
    
    html += `
        <div style="margin-top: 30px; display: flex; gap: 10px; justify-content: flex-end;">
            <button class="btn btn-secondary" onclick="window.open('pages/admin.php', '_blank')">
                <i class="fas fa-cogs"></i> Yönetim Paneli
            </button>
        </div>
    `;
    
    content.innerHTML = html;
    modal.classList.add('active');
    
    // Port hover tooltip'leri aktif et
    setTimeout(() => {
        attachPortHoverTooltips('.port-item');
    }, 100);
};

        window.removeFiberBridgeConnection = async function(panelId, portNumber) {
            if (!confirm('Bu köprü bağlantısını kaldırmak istediğinize emin misiniz?')) return;
            try {
                showLoading();
                const response = await fetch('actions/disconnectFiberPort.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        type: 'fiber_port',
                        panel_id: parseInt(panelId),
                        port: parseInt(portNumber),
                        user: 'ui'
                    })
                });
                const result = await response.json();
                if (result.success) {
                    showToast('Köprü bağlantısı kaldırıldı', 'success');
                    await loadData();
                    window.showPanelDetail(panelId, 'fiber');
                } else {
                    throw new Error(result.error || result.message || 'Bağlantı kaldırılamadı');
                }
            } catch (error) {
                console.error('Köprü kaldırma hatası:', error);
                showToast('Köprü kaldırılamadı: ' + error.message, 'error');
            } finally {
                hideLoading();
            }
        };

        window.deletePanel = async function(panelId, panelType) {
            const panel = panelType === 'patch' 
                ? patchPanels.find(p => p.id == panelId)
                : fiberPanels.find(p => p.id == panelId);
            
            if (!panel) return;
            
            if (!confirm(`${panelType === 'patch' ? 'Patch' : 'Fiber'} Panel ${panel.panel_letter} silinecek. Emin misiniz?`)) {
                return;
            }
            
            try {
                const response = await fetch(`api/delete.php?type=${panelType}_panel&id=${panelId}`);
                const result = await response.json();
                
                if (result.status === 'deleted') {
                    showToast('Panel silindi', 'success');
                    document.getElementById('panel-detail-modal').classList.remove('active');
                    await loadData();
                    loadRacksPage();
                } else {
                    throw new Error(result.message || 'Silme başarısız');
                }
            } catch (error) {
                console.error('Panel silme hatası:', error);
                showToast('Panel silinemedi: ' + error.message, 'error');
            }
        };

        // ============================================
        // RACK DETAIL FONKSİYONU - GÜNCELLENDİ
        // ============================================

        function showRackDetail(rack) {
            const modal = document.getElementById('rack-detail-modal');
            const title = document.getElementById('rack-detail-title');
            const content = document.getElementById('rack-detail-content');
            
            title.textContent = `${rack.name} - ${rack.location}`;
            
            // Bu rack'teki tüm cihazları bul
            const rackSwitches = switches.filter(s => s.rack_id == rack.id);
            const rackPatchPanels = patchPanels.filter(p => p.rack_id == rack.id);
            const rackFiberPanels = fiberPanels.filter(fp => fp.rack_id == rack.id);
            const rackRackDevices = rackDevices.filter(d => d.rack_id == rack.id);
            
            let html = `
                <div style="margin-bottom: 30px;">
                    <div style="display: flex; gap: 20px; margin-bottom: 20px;">
                        <div style="flex: 1;">
                            <h4 style="color: var(--primary); margin-bottom: 10px;">Rack Bilgileri</h4>
                            <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px;">
                                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                    <span style="color: var(--text-light);">Slot Sayısı:</span>
                                    <span style="color: var(--text);">${rack.slots || 42}</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                    <span style="color: var(--text-light);">Açıklama:</span>
                                    <span style="color: var(--text);">${rack.description || 'Yok'}</span>
                                </div>
                            </div>
                        </div>
                        <div style="flex: 1;">
                            <h4 style="color: var(--primary); margin-bottom: 10px;">İstatistikler</h4>
                            <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px;">
                                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                    <span style="color: var(--text-light);">Switch:</span>
                                    <span style="color: var(--text);">${rackSwitches.length}</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                    <span style="color: var(--text-light);">Patch Panel:</span>
                                    <span style="color: var(--text);">${rackPatchPanels.length}</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                    <span style="color: var(--text-light);">Fiber Panel:</span>
                                    <span style="color: var(--text);">${rackFiberPanels.length}</span>
                                </div>
                                ${rackRackDevices.length > 0 ? `
                                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                    <span style="color: var(--text-light);">Server/Hub SW:</span>
                                    <span style="color: var(--text);">${rackRackDevices.length}</span>
                                </div>` : ''}
                                <div style="display: flex; justify-content: space-between;">
                                    <span style="color: var(--text-light);">Dolu Slot:</span>
                                    <span style="color: var(--text);">${rackSwitches.length + rackPatchPanels.length + rackFiberPanels.length + rackRackDevices.length}/${rack.slots || 42}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <h4 style="color: var(--primary); margin-bottom: 15px;">Kabin Görünümü</h4>
                    <div style="background:#0f172a;border:1px solid var(--border);border-radius:10px;padding:10px 12px;max-height:420px;overflow-y:auto;">
            `;

            // Tüm slotları kart olarak oluştur
            const CORE_UNIT_HEIGHT = 8; // Cisco Catalyst 9606R → 8U
            let skipUntilSlot = 0; // core switch kartı çizildikten sonra sonraki slotları atla
            for (let slotNum = 1; slotNum <= (rack.slots || 42); slotNum++) {
                const sw       = rackSwitches.find(s => s.position_in_rack == slotNum);
                const panel    = rackPatchPanels.find(p => p.position_in_rack == slotNum);
                const fpanel   = rackFiberPanels.find(fp => fp.position_in_rack == slotNum);
                const rackDev  = rackRackDevices.find(d => d.position_in_rack == slotNum);

                // Core switch tarafından kaplanan slotları atla
                if (slotNum < skipUntilSlot) {
                    continue;
                }

                if (sw) {
                    // Switch kartı
                    const isCore   = (sw.is_core == 1 || sw.is_core === true || sw.is_core === '1');
                    const conns   = portConnections[sw.id] || [];
                    const total   = parseInt(sw.ports) || 24;
                    const display = Math.min(total, 48);
                    const portDots = Array.from({length: display}, (_, i) => {
                        const c = conns.find(x => x.port == (i + 1));
                        let hasData = c && ((c.ip && c.ip.trim()) || (c.mac && c.mac.trim()) || (c.device && c.device.trim() && c.type !== 'BOŞ'));
                        // For core switch: also detect virtual_core_reverse connections
                        if (!hasData && c && c.connection_info_preserved) {
                            try {
                                const vcp = JSON.parse(c.connection_info_preserved);
                                if (vcp && vcp.type === 'virtual_core_reverse') hasData = true;
                            } catch(e) {}
                        }
                        // Only show green when port has data AND link is up (not is_down)
                        const used = hasData && !(c && c.is_down);
                        return `<span style="display:inline-block;width:6px;height:6px;border-radius:1px;margin:2px;background:${used ? '#10b981' : '#1e3a2f'};"></span>`;
                    }).join('');
                    const isOnline = sw.status === 'online';
                    // Core switch için 8U yüksekliğinde özel kart, min-height ile göster
                    const coreStyle = isCore
                        ? `min-height:${CORE_UNIT_HEIGHT * 22}px;background:linear-gradient(135deg,#0d1f35 0%,#0a1628 100%);border-color:#7c3aed;`
                        : '';
                    const coreBadge = isCore
                        ? `<span style="font-size:0.7rem;background:#7c3aed;color:#fff;border-radius:4px;padding:1px 5px;margin-left:6px;">CORE ${CORE_UNIT_HEIGHT}U</span>`
                        : '';
                    if (isCore) {
                        skipUntilSlot = slotNum + CORE_UNIT_HEIGHT; // sonraki 7 slotu atla
                    }
                    html += `
                        <div style="background:#0d1f35;border:2px solid #2563eb;border-radius:8px;padding:10px 12px;margin-bottom:6px;cursor:pointer;${coreStyle}"
                             onclick="showSwitchDetail(${JSON.stringify(sw).replace(/"/g,'&quot;')}); document.getElementById('rack-detail-modal').classList.remove('active');">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                                <span style="font-weight:700;color:#e2e8f0;font-size:0.95rem;">${sw.name}${coreBadge}</span>
                                <span style="font-size:0.75rem;color:${isOnline ? '#10b981' : '#ef4444'};display:flex;align-items:center;gap:4px;">
                                    <i class="fas fa-circle" style="font-size:0.6rem;"></i>${isOnline ? 'Online' : 'Offline'}
                                </span>
                            </div>
                            ${sw.ip ? `<div style="font-size:0.78rem;color:#64748b;margin-bottom:5px;">***</div>` : ''}
                            ${isCore ? `<div style="font-size:0.75rem;color:#a78bfa;margin-bottom:8px;">Cisco Catalyst 9606R · Slot ${slotNum}–${slotNum+CORE_UNIT_HEIGHT-1}</div>` : ''}
                            <div style="line-height:1;">${portDots}</div>
                        </div>`;
                } else if (panel) {
                    // Patch panel kartı – port ızgarası
                    const pPorts   = patchPorts[panel.id] || [];
                    const pTotal   = parseInt(panel.total_ports) || 24;
                    const pDisplay = Math.min(pTotal, 48);
                    const pDots = Array.from({length: pDisplay}, (_, i) => {
                        const pp = pPorts.find(x => parseInt(x.port_number) === (i + 1));
                        const used = pp && pp.status === 'active';
                        return `<span style="display:inline-block;width:6px;height:6px;border-radius:1px;margin:2px;background:${used ? '#10b981' : '#374151'};"></span>`;
                    }).join('');
                    html += `
                        <div style="background:#1a1200;border:2px solid #d97706;border-radius:8px;padding:10px 12px;margin-bottom:6px;cursor:pointer;"
                             onclick="showPanelDetail(${panel.id}, 'patch'); document.getElementById('rack-detail-modal').classList.remove('active');">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                                <span style="font-weight:700;color:#fbbf24;font-size:0.95rem;"><i class="fas fa-th-large" style="margin-right:5px;font-size:0.8rem;"></i>Panel ${panel.panel_letter}</span>
                                <span style="font-size:0.78rem;color:#92400e;">${pTotal}P</span>
                            </div>
                            <div style="line-height:1;">${pDots}</div>
                        </div>`;
                } else if (fpanel) {
                    // Fiber panel kartı – port ızgarası
                    const fpPorts   = fiberPorts[fpanel.id] || [];
                    const fpTotal   = parseInt(fpanel.total_fibers) || 24;
                    const fpDisplay = Math.min(fpTotal, 48);
                    const fpDots = Array.from({length: fpDisplay}, (_, i) => {
                        const fp2 = fpPorts.find(x => parseInt(x.port_number) === (i + 1));
                        const used = fp2 && (fp2.status === 'active' || (fp2.connected_fiber_panel_id && fp2.connected_fiber_panel_port));
                        return `<span style="display:inline-block;width:6px;height:6px;border-radius:1px;margin:2px;background:${used ? '#10b981' : '#374151'};"></span>`;
                    }).join('');
                    html += `
                        <div style="background:#001a20;border:2px solid #0891b2;border-radius:8px;padding:10px 12px;margin-bottom:6px;cursor:pointer;"
                             onclick="showPanelDetail(${fpanel.id}, 'fiber'); document.getElementById('rack-detail-modal').classList.remove('active');">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                                <span style="font-weight:700;color:#22d3ee;font-size:0.95rem;"><i class="fas fa-satellite-dish" style="margin-right:5px;font-size:0.8rem;"></i>Fiber Panel ${fpanel.panel_letter}</span>
                                <span style="font-size:0.78rem;color:#164e63;">${fpTotal}F</span>
                            </div>
                            <div style="line-height:1;">${fpDots}</div>
                        </div>`;
                } else if (rackDev) {
                    // Server veya Hub SW kartı
                    const isHub = rackDev.device_type === 'hub_sw';
                    const devColor  = isHub ? '#fbbf24' : '#c4b5fd';
                    const devBorder = isHub ? '#d97706' : '#7c3aed';
                    const devBg     = isHub ? '#1a1400' : '#120d1a';
                    const devIcon   = isHub ? 'fa-sitemap' : 'fa-server';
                    const devLabel  = isHub ? 'Hub SW' : 'Server';
                    const unitSize  = parseInt(rackDev.unit_size) || 1;
                    const unitBadge = unitSize > 1 ? `<span style="font-size:0.7rem;background:${devBorder};color:#fff;border-radius:4px;padding:1px 5px;margin-left:6px;">${unitSize}U</span>` : '';
                    const portBadge = (() => {
                        const parts = [];
                        if (rackDev.ports > 0)       parts.push(`${rackDev.ports}P`);
                        if (rackDev.fiber_ports > 0) parts.push(`${rackDev.fiber_ports}FP`);
                        return parts.length
                            ? `<span style="font-size:0.78rem;color:${devColor};opacity:0.7;">${parts.join(' / ')}</span>`
                            : '';
                    })();
                    const notesLine = rackDev.notes ? `<div style="font-size:0.75rem;color:#64748b;margin-top:4px;">${escapeHtml(rackDev.notes)}</div>` : '';
                    const devStyle  = unitSize > 1 ? `min-height:${unitSize * 22}px;` : '';
                    if (unitSize > 1) { skipUntilSlot = slotNum + unitSize; }
                    // Port dots: green if a patch panel port is connected to this Hub SW port
                    const totalPortDots = (rackDev.ports || 0) + (rackDev.fiber_ports || 0);
                    const portDotDisplay = Math.min(totalPortDots, 48);
                    // Pre-build set of connected port numbers from all patch ports
                    const connectedRdPorts = new Set();
                    Object.values(patchPorts).forEach(panelPorts => {
                        panelPorts.forEach(pp => {
                            if (!pp.connection_details) return;
                            try {
                                const cd = typeof pp.connection_details === 'string'
                                    ? JSON.parse(pp.connection_details) : pp.connection_details;
                                if (cd && cd.rack_device_id == rackDev.id && cd.rack_device_port) {
                                    connectedRdPorts.add(parseInt(cd.rack_device_port));
                                }
                            } catch(e) {}
                        });
                    });
                    const devDots = portDotDisplay > 0 ? Array.from({length: portDotDisplay}, (_, i) => {
                        const portIdx = i + 1;
                        const isFiberDot = i >= (rackDev.ports || 0);
                        const isPortConnected = connectedRdPorts.has(portIdx);
                        const bg = isPortConnected ? '#10b981' : (isFiberDot ? '#164e63' : '#374151');
                        return `<span style="display:inline-block;width:6px;height:6px;border-radius:1px;margin:2px;background:${bg};"></span>`;
                    }).join('') : '';
                    const hasPortsToManage = ((rackDev.ports || 0) + (rackDev.fiber_ports || 0)) > 0;
                    html += `
                        <div style="background:${devBg};border:2px solid ${devBorder};border-radius:8px;padding:10px 12px;margin-bottom:6px;${devStyle}${hasPortsToManage ? 'cursor:pointer;' : ''}"${hasPortsToManage ? ` onclick="openHubSwPortModal(${rackDev.id})"` : ''}>
                            <div style="display:flex;justify-content:space-between;align-items:center;${devDots ? 'margin-bottom:6px;' : ''}">
                                <span style="font-weight:700;color:${devColor};font-size:0.95rem;">
                                    <i class="fas ${devIcon}" style="margin-right:5px;font-size:0.8rem;"></i>${escapeHtml(rackDev.name)}${unitBadge}
                                </span>
                                <span style="display:flex;align-items:center;gap:8px;">
                                    ${portBadge}
                                    <span style="font-size:0.75rem;background:rgba(0,0,0,0.3);color:${devColor};border-radius:4px;padding:1px 6px;">${devLabel}</span>
                                    ${hasPortsToManage ? `<i class="fas fa-chevron-right" style="color:${devColor};font-size:0.7rem;opacity:0.7;"></i>` : ''}
                                </span>
                            </div>
                            ${devDots ? `<div style="line-height:1;">${devDots}</div>` : ''}
                            ${notesLine}
                        </div>`;
                } else {
                    // Boş slot - ince çizgi
                    html += `<div style="height:6px;background:rgba(30,41,59,0.6);border-radius:3px;margin-bottom:4px;border:1px solid rgba(51,65,85,0.4);" title="Slot ${slotNum}: Boş"></div>`;
                }
            }

            html += `
                    </div>
                </div>
                
                <div style="margin-top: 20px; display: flex; gap: 10px; justify-content: flex-end; flex-wrap: wrap;">
                    <button class="btn btn-secondary" onclick="window.open('pages/admin.php', '_blank')">
                        <i class="fas fa-cogs"></i> Yönetim Paneli
                    </button>
                </div>
            `;
            
            content.innerHTML = html;
            modal.classList.add('active');
        }

        // ============================================
        // HELPER FONKSİYON: rackId ile açık modalda düzenleme açmak
        // ============================================

        function openRackModalForRack(rackId) {
            const rackObj = racks.find(r => r.id == rackId);
            if (!rackObj) {
                showToast('Rack bulunamadı', 'error');
                return;
            }
            openRackModal(rackObj);
        }

        function switchPage(pageName) {
            console.log('Switching to page:', pageName);
            
            // Hide all pages
            document.querySelectorAll('.page-content').forEach(page => {
                page.classList.remove('active');
            });
            
            // Show selected page
            const page = document.getElementById(`page-${pageName}`);
            if (page) {
                page.classList.add('active');
                updatePageContent(pageName);
            }
            
            // Update nav items
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
                if (item.dataset.page === pageName) {
                    item.classList.add('active');
                }
            });
            
            // Hide detail panel
            hideDetailPanel();
        }

        function updatePageContent(pageName) {
            console.log('Updating page content:', pageName);
            switch (pageName) {
                case 'dashboard':
                    loadDashboard();
                    break;
                case 'racks':
                    loadRacksPage();
                    break;
                case 'switches':
                    loadSwitchesPage();
                    break;
                case 'topology':
                    loadTopologyPage();
                    break;
                case 'port-alarms':
                    loadPortAlarmsPage();
                    break;
                case 'device-import':
                    // Device import page is loaded via iframe
                    // Note: iframe includes sandbox attribute for security
                    // and error handling for loading failures
                    break;
                case 'reports':
                    // Reports page is loaded via iframe
                    break;
            }
        }

        function loadRacksPage() {
            const container = document.getElementById('racks-container');
            if (!container) return;
            
            container.innerHTML = '';
            
            racks.forEach(rack => {
                const rackSwitches = switches.filter(s => s.rack_id == rack.id);
                const rackPatchPanels = patchPanels.filter(p => p.rack_id == rack.id);
                const rackFiberPanels = fiberPanels.filter(fp => fp.rack_id == rack.id);
                const rackHubSwitches = (rackDevices || []).filter(d => d.rack_id == rack.id && d.device_type === 'hub_sw');

                const totalSlots = rack.slots || 42;
                const filled = rackSwitches.length + rackPatchPanels.length + rackFiberPanels.length + rackHubSwitches.length;
                const filledPct = Math.min(100, Math.round(filled / totalSlots * 100));
                const usageColor = filledPct > 80 ? '#ef4444' : filledPct > 50 ? '#f59e0b' : '#10b981';

                // Slot dot strip
                const slotDots = Array.from({length: Math.min(totalSlots, 52)}, (_, i) => {
                    const sn = i + 1;
                    const hasSw  = rackSwitches.find(s => s.position_in_rack == sn);
                    const hasPp  = rackPatchPanels.find(p => p.position_in_rack == sn);
                    const hasFp  = rackFiberPanels.find(f => f.position_in_rack == sn);
                    const hasRd  = rackHubSwitches.find(d => d.position_in_rack == sn);
                    const cls = hasSw ? 'sw-dot' : hasPp ? 'pp-dot' : hasFp ? 'fp-dot' : hasRd ? 'sw-dot' : 'em-dot';
                    const tip = hasSw ? hasSw.name : hasPp ? `Panel ${hasPp.panel_letter}` : hasFp ? `Fiber ${hasFp.panel_letter}` : hasRd ? hasRd.name : `Slot ${sn} (Boş)`;
                    return `<span class="slot-dot ${cls}" title="${tip}"></span>`;
                }).join('');

                const rackCard = document.createElement('div');
                rackCard.className = 'rack-card';
                rackCard.innerHTML = `
                    <div class="rack-summary">
                        <div class="rack-slot-strip">${slotDots}</div>
                        <div class="rack-stat-badges">
                            ${rackSwitches.length   > 0 ? `<span class="rstat sw"><i class="fas fa-network-wired"></i> ${rackSwitches.length} SW</span>` : ''}
                            ${rackPatchPanels.length > 0 ? `<span class="rstat pp"><i class="fas fa-th"></i> ${rackPatchPanels.length} Panel</span>` : ''}
                            ${rackFiberPanels.length > 0 ? `<span class="rstat fp"><i class="fas fa-link"></i> ${rackFiberPanels.length} Fiber</span>` : ''}
                            ${rackHubSwitches.length > 0 ? `<span class="rstat sw" style="opacity:0.75;"><i class="fas fa-sitemap"></i> ${rackHubSwitches.length} Hub SW</span>` : ''}
                            <span class="rstat em">${totalSlots - filled} Boş</span>
                        </div>
                        <div class="rack-usage-bar">
                            <div class="rack-usage-fill" style="width:${filledPct}%;background:${usageColor};"></div>
                        </div>
                    </div>
                    <div class="rack-header">
                        <div class="rack-title">${rack.name}</div>
                        <div class="rack-switches">${filled}/${totalSlots} Slot</div>
                    </div>
                    <div class="rack-info">
                        <div class="rack-location">
                            <i class="fas fa-map-marker-alt"></i>
                            <span>${rack.location}</span>
                        </div>
                        <div>${totalSlots} Slot</div>
                    </div>
                    <div style="display: flex; gap: 5px; margin-top: 15px; flex-wrap: wrap;">
                        <button class="btn btn-secondary" data-view-rack="${rack.id}" style="flex: 1;">
                            <i class="fas fa-eye"></i> Detay
                        </button>
                    </div>
                `;
                
                container.appendChild(rackCard);
                
                // Detay butonu
                const viewBtn = rackCard.querySelector(`[data-view-rack="${rack.id}"]`);
                viewBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    showRackDetail(rack);
                });
            });
        }

        // Belirli bir rack için switch modalı açma
        function openSwitchModalForRack(rackId) {
            openSwitchModal();
            setTimeout(() => {
                const rackSelect = document.getElementById('switch-rack');
                if (rackSelect) {
                    rackSelect.innerHTML = '';
                    
                    racks.forEach(rack => {
                        const option = document.createElement('option');
                        option.value = rack.id;
                        option.textContent = `${rack.name} (${rack.location})`;
                        rackSelect.appendChild(option);
                    });
                    
                    rackSelect.value = rackId;
                }
            }, 100);
        }

        function loadSwitchesPage() {
            const container = document.getElementById('switches-container');
            if (!container) return;
            
            const tab = document.querySelector('.tab-btn.active')?.dataset.tab || 'all-switches';
            
            let filteredSwitches = switches;
            if (tab === 'online-switches') {
                filteredSwitches = switches.filter(s => s.status === 'online');
            } else if (tab === 'offline-switches') {
                filteredSwitches = switches.filter(s => s.status === 'offline');
            }
            
            container.innerHTML = '';
            
            if (filteredSwitches.length === 0) {
                container.innerHTML = `
                    <div style="grid-column: 1/-1; text-align: center; padding: 60px; color: var(--text-light);">
                        <i class="fas fa-network-wired" style="font-size: 4rem; margin-bottom: 20px;"></i>
                        <h3 style="margin-bottom: 10px;">Switch bulunamadı</h3>
                        <p>Yeni switch eklemek için <a href="pages/admin.php" target="_blank" style="color:var(--primary)">Admin Paneli</a>'ni kullanın</p>
                    </div>
                `;
                return;
            }
            
            filteredSwitches.forEach(sw => {
                const connections = portConnections[sw.id] || [];
                const rack = racks.find(r => r.id === sw.rack_id);
                const isOnline = sw.status === 'online';
                const totalPorts = parseInt(sw.ports) || 0;
                const usedCount = connections.filter(c => {
                    if (c.is_down) return false;
                    if (c.device && c.device.trim() !== '' && c.type !== 'BOŞ') return true;
                    if (c.connection_info_preserved) {
                        try { const vcp = JSON.parse(c.connection_info_preserved); if (vcp?.type === 'virtual_core_reverse') return true; } catch(e) {}
                    }
                    return false;
                }).length;
                const usedPct = totalPorts > 0 ? Math.min(100, Math.round(usedCount / totalPorts * 100)) : 0;

                // Port dot strip – all ports, up to 48
                const portDots = Array.from({length: Math.min(totalPorts, 48)}, (_, i) => {
                    const conn = connections.find(c => c.port === (i + 1));
                    let isVCR = false;
                    if (conn && conn.connection_info_preserved) {
                        try { const vcp = JSON.parse(conn.connection_info_preserved); isVCR = vcp?.type === 'virtual_core_reverse'; } catch(e) {}
                    }
                    // A port is "active" (green) only when it has connection data AND link is up.
                    // Ports with device/ip/mac but is_down=true show as inactive (red/dim).
                    const hasData = isVCR || (conn && (
                        (conn.ip && conn.ip.trim()) ||
                        (conn.mac && conn.mac.trim()) ||
                        (conn.device && conn.device.trim() && conn.type !== 'BOŞ')
                    ));
                    const used = hasData && !(conn && conn.is_down);
                    const tip = conn && conn.device ? conn.device : `Port ${i+1}`;
                    return `<span class="sw-port-dot ${used ? 'used' : 'free'}" data-port="${i+1}" title="${tip}"></span>`;
                }).join('');

                const switchCard = document.createElement('div');
                switchCard.className = 'rack-card';
                const isCoreSw = sw.is_core == 1 || sw.is_core === true || sw.is_core === '1';

                // Health badges (from snmp_devices via getData join) — always show all 4 pills
                const isCBS350  = sw.model && /CBS350/i.test(sw.model);
                const temp      = sw.snmp_temperature_c !== null && sw.snmp_temperature_c !== undefined ? parseFloat(sw.snmp_temperature_c) : null;
                const cpu       = sw.snmp_cpu_1min !== null && sw.snmp_cpu_1min !== undefined ? parseFloat(sw.snmp_cpu_1min) : null;
                const mem       = sw.snmp_memory_usage !== null && sw.snmp_memory_usage !== undefined ? parseFloat(sw.snmp_memory_usage) : null;
                const fanSt     = (sw.snmp_fan_status && sw.snmp_fan_status !== 'N/A') ? sw.snmp_fan_status : null;
                const poeNom    = sw.snmp_poe_nominal_w !== null && sw.snmp_poe_nominal_w !== undefined ? parseInt(sw.snmp_poe_nominal_w) : null;
                const poeCon    = sw.snmp_poe_consumed_w !== null && sw.snmp_poe_consumed_w !== undefined ? parseInt(sw.snmp_poe_consumed_w) : 0;
                const poeAP     = sw.snmp_poe_active_ports !== null && sw.snmp_poe_active_ports !== undefined ? parseInt(sw.snmp_poe_active_ports) : null;
                const poeTP     = sw.snmp_poe_total_ports  !== null && sw.snmp_poe_total_ports  !== undefined ? parseInt(sw.snmp_poe_total_ports)  : null;
                const mkPill  = (label, value, color, bg) =>
                    `<span style="display:inline-flex;flex-direction:column;align-items:center;gap:1px;background:${bg};border:1px solid ${color}33;border-radius:6px;padding:2px 7px;min-width:44px;">` +
                    `<span style="font-size:8px;color:#64748b;text-transform:uppercase;letter-spacing:0.4px;">${label}</span>` +
                    `<span style="font-size:11px;font-weight:700;color:${color};">${value}</span></span>`;
                const headerHealthPills = (() => {
                    const tColor = temp !== null ? (temp >= 70 ? '#ef4444' : temp >= 55 ? '#f59e0b' : '#10b981') : '#475569';
                    const tBg    = temp !== null ? (temp >= 70 ? 'rgba(239,68,68,0.12)' : temp >= 55 ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)') : 'rgba(71,85,105,0.08)';
                    const fColor = fanSt !== null ? (fanSt === 'OK' ? '#10b981' : fanSt === 'WARNING' ? '#f59e0b' : '#ef4444') : '#475569';
                    const fBg    = fanSt !== null ? (fanSt === 'OK' ? 'rgba(16,185,129,0.12)' : fanSt === 'WARNING' ? 'rgba(245,158,11,0.12)' : 'rgba(239,68,68,0.12)') : 'rgba(71,85,105,0.08)';
                    const cColor = cpu  !== null ? (cpu  >= 80 ? '#ef4444' : cpu  > 20 ? '#f59e0b' : '#10b981') : '#475569';
                    const cBg    = cpu  !== null ? (cpu  >= 80 ? 'rgba(239,68,68,0.12)' : cpu  > 20 ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)') : 'rgba(71,85,105,0.08)';
                    const mColor = mem  !== null ? (mem  >= 85 ? '#ef4444' : mem  > 30 ? '#f59e0b' : '#10b981') : '#475569';
                    const mBg    = mem  !== null ? (mem  >= 85 ? 'rgba(239,68,68,0.12)' : mem  > 30 ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)') : 'rgba(71,85,105,0.08)';
                    const poePct = poeNom !== null && poeNom > 0 ? Math.round(poeCon / poeNom * 100) : null;
                    const pColor = poePct !== null ? (poePct >= 90 ? '#ef4444' : poePct >= 75 ? '#f59e0b' : '#10b981') : '#475569';
                    const pBg    = poePct !== null ? (poePct >= 90 ? 'rgba(239,68,68,0.12)' : poePct >= 75 ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)') : 'rgba(71,85,105,0.08)';
                    const paColor = poeAP !== null ? (poeAP > 35 ? '#ef4444' : poeAP > 25 ? '#f59e0b' : '#10b981') : '#475569';
                    const paBg    = poeAP !== null ? (poeAP > 35 ? 'rgba(239,68,68,0.12)' : poeAP > 25 ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)') : 'rgba(71,85,105,0.08)';
                    return `<div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center;">` +
                        mkPill('SICAKLIK', temp !== null ? temp + '°C' : '—', tColor, tBg) +
                        mkPill('FAN',      fanSt !== null ? fanSt : '—', fColor, fBg) +
                        mkPill('CPU',      cpu  !== null ? cpu  + '%'  : '—', cColor, cBg) +
                        (!isCBS350 ? mkPill('RAM', mem !== null ? mem + '%' : '—', mColor, mBg) : '') +
                        (poeNom !== null ? mkPill('POE', poePct + '%', pColor, pBg) : '') +
                        (poeAP !== null && poeTP !== null && poeTP > 0 ? mkPill('POE PORT', poeAP + '/' + poeTP, paColor, paBg) : '') +
                        `</div>`;
                })();

                switchCard.innerHTML = `
                    <div class="sw-card-top" style="flex-wrap:wrap;gap:6px;">
                        <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
                            <span class="sw-brand-badge" style="${isCoreSw ? 'background:linear-gradient(135deg,#fbbf24,#f59e0b);color:#1e293b;' : ''}">${sw.brand || 'SW'}</span>
                            ${isCoreSw ? '<span style="background:#fbbf24;color:#1e293b;font-size:0.7rem;font-weight:800;padding:2px 7px;border-radius:10px;letter-spacing:1px;">CORE</span>' : ''}
                        </div>
                        ${headerHealthPills}
                        <span class="sw-status-indicator ${isOnline ? 'online' : 'offline'}" style="margin-left:auto;flex-shrink:0;">
                            <span class="sw-status-dot2 ${isOnline ? 'online' : 'offline'}"></span>
                            ${isOnline ? 'Online' : 'Offline'}
                        </span>
                    </div>
                    <div style="margin-bottom:10px;">
                        <div class="rack-title" style="font-size:1.15rem;margin-bottom:4px;">${sw.name}</div>
                        <div style="font-size:0.82rem;color:var(--text-light);display:flex;justify-content:space-between;">
                            <span><i class="fas fa-cube" style="margin-right:4px;color:#60a5fa;"></i>${rack?.name || '—'}</span>
                            <span style="color:${usedPct > 80 ? '#ef4444' : '#94a3b8'}">${usedCount}/${totalPorts} Port</span>
                        </div>
                    </div>
                    <div class="sw-port-strip">${portDots}</div>
                    <div class="sw-usage-bar">
                        <div class="sw-usage-fill" style="width:${usedPct}%;"></div>
                    </div>
                    <button class="btn btn-primary" style="width:100%;margin-top:10px;${isCoreSw ? 'background:linear-gradient(135deg,#d97706,#b45309);' : ''}" data-view-switch="${sw.id}">
                        <i class="fas fa-eye"></i> Görüntüle
                    </button>
                `;
                
                container.appendChild(switchCard);
                
                // Add event listeners
                const viewBtn = switchCard.querySelector(`[data-view-switch="${sw.id}"]`);
                viewBtn.addEventListener('click', () => {
                    showSwitchDetail(sw);
                });
                
                // Click on card to view details
                switchCard.addEventListener('click', (e) => {
                    if (!e.target.closest('button')) {
                        const dotEl = e.target.closest('.sw-port-dot');
                        const portNum = dotEl ? parseInt(dotEl.dataset.port) : null;
                        showSwitchDetail(sw, portNum);
                    }
                });
            });

        }

        function loadTopologyPage() {
            // Populate rack filter select
            const sel = document.getElementById('topo-rack-select');
            if (sel && sel.options.length <= 1) {
                (typeof racks !== 'undefined' ? racks : []).forEach(rk => {
                    const o = document.createElement('option');
                    o.value = rk.id;
                    o.textContent = rk.name + (rk.location ? ' (' + rk.location + ')' : '');
                    sel.appendChild(o);
                });
            }
            topoRender();
        }

        // ══════════════════════════════════════════════════════════════════
        // TOPOLOGY / CABLE TRACE ENGINE
        // ══════════════════════════════════════════════════════════════════
        let topoView = 'all';   // 'all' | 'trace'
        let topoRackFilter = ''; // rack id or '' for all
        let topoNodes = [];     // { id, type, label, x, y, color, ports?, data }
        let topoEdges = [];     // { from, to, label, color }
        let topoHitBoxes = [];  // { x,y,w,h, nodeId, portIndex? }
        let topoHighlight = null; // nodeId or null
        let topoTracePath = [];

        const TOPO_COLORS = {
            switch:      { fill:'#1e3a5f', stroke:'#3b82f6', text:'#93c5fd' },
            patch_panel: { fill:'#3d2a00', stroke:'#f59e0b', text:'#fcd34d' },
            fiber_panel: { fill:'#0d3320', stroke:'#10b981', text:'#6ee7b7' },
            rack:        { fill:'#1e293b', stroke:'#334155', text:'#64748b' }
        };

        function topoSetView(v) {
            topoView = v;
            document.getElementById('topo-btn-all').className   = 'btn ' + (v==='all'   ? 'btn-primary' : '');
            const traceBtn = document.getElementById('topo-btn-trace');
            if (traceBtn) traceBtn.style.background = v==='trace' ? 'rgba(139,92,246,.4)' : 'rgba(139,92,246,.15)';
            document.getElementById('topo-trace-hint').style.display   = v==='trace' ? '' : 'none';
            if (v !== 'trace') {
                document.getElementById('topo-trace-panel').style.display = 'none';
                topoHighlight = null;
                topoTracePath = [];
                topoRender();
            }
        }

        function topoReset() {
            topoHighlight = null;
            topoTracePath = [];
            document.getElementById('topo-trace-panel').style.display = 'none';
            topoRender();
        }

        function topoFilterRack(rackId) {
            topoRackFilter = rackId;
            topoHighlight  = null;
            topoTracePath  = [];
            document.getElementById('topo-trace-panel').style.display = 'none';
            topoRender();
        }

        function topoRender() {
            const canvas = document.getElementById('topo-canvas');
            if (!canvas) return;
            const wrap   = document.getElementById('topo-scroll-wrap');
            if (!wrap) return;

            // Gather data from global variables populated by getData.php response
            const sw  = (typeof switches      !== 'undefined' ? switches      : []);
            const pp  = (typeof patchPanels   !== 'undefined' ? patchPanels   : []);
            const fp  = (typeof fiberPanels   !== 'undefined' ? fiberPanels   : []);
            const rks = (typeof racks         !== 'undefined' ? racks         : []);
            const pco = (typeof portConnections !== 'undefined' ? portConnections : {});

            // Layout: group by rack, each rack is a column
            const CARD_W = 220, CARD_H_SW = 140, CARD_H_P = 70, RACK_GAP_X = 60, ITEM_GAP_Y = 18;
            const RACK_PAD = 20, START_X = 40, START_Y = 40;

            topoNodes = [];
            topoEdges = [];
            topoHitBoxes = [];

            let totalWidth = START_X;
            // Apply rack filter if set
            const visibleRacks = topoRackFilter
                ? rks.filter(r => r.id == topoRackFilter)
                : rks;

            visibleRacks.forEach((rack, ri) => {
                const rSwitches    = sw.filter(s => s.rack_id == rack.id);
                const rPatch       = pp.filter(p => p.rack_id == rack.id);
                const rFiber       = fp.filter(f => f.rack_id == rack.id);

                // Combine all items and sort by physical slot (position_in_rack)
                const combined = [
                    ...rSwitches.map(s => ({ type:'switch',      data:s, height: (s.is_core == 1 || s.is_core === true || s.is_core === '1') ? CARD_H_SW * 3 : CARD_H_SW, pos: parseInt(s.position_in_rack) || 999 })),
                    ...rPatch.map(p =>    ({ type:'patch_panel',  data:p, height: CARD_H_P,  pos: parseInt(p.position_in_rack) || 999 })),
                    ...rFiber.map(f =>    ({ type:'fiber_panel',  data:f, height: CARD_H_P,  pos: parseInt(f.position_in_rack) || 999 }))
                ].sort((a, b) => a.pos - b.pos);

                let colHeight = RACK_PAD;
                const items = [];

                combined.forEach(item => {
                    items.push(item);
                    colHeight += item.height + ITEM_GAP_Y;
                });
                colHeight += RACK_PAD;

                const colX = totalWidth;
                const colY = START_Y;

                // Rack background node (virtual)
                topoNodes.push({
                    id: 'rack-' + rack.id,
                    type: 'rack',
                    label: rack.name,
                    sublabel: rack.location || '',
                    x: colX - RACK_PAD,
                    y: colY - RACK_PAD,
                    w: CARD_W + RACK_PAD * 2,
                    h: colHeight + RACK_PAD * 2
                });

                let curY = colY + RACK_PAD;
                items.forEach(item => {
                    const d = item.data;
                    const nid = item.type + '-' + d.id;
                    topoNodes.push({
                        id:      nid,
                        type:    item.type,
                        dataId:  d.id,
                        label:   d.name || (d.panel_letter ? 'Panel ' + d.panel_letter : 'Fiber ' + (d.panel_letter||'')),
                        sublabel: item.type==='switch' ? (d.ip || '') : (item.type==='patch_panel' ? `${d.total_ports||24}P` : `${d.total_fibers||24}F`),
                        x:       colX,
                        y:       curY,
                        w:       CARD_W,
                        h:       item.height,
                        ports:   item.type==='switch' ? (pco[d.id] || []) : [],
                        status:  d.status || 'unknown'
                    });
                    curY += item.height + ITEM_GAP_Y;
                });

                totalWidth += CARD_W + RACK_GAP_X + RACK_PAD * 2;
            });

            // Edges from switch ports → patch panels
            sw.forEach(s => {
                const ports = pco[s.id] || [];
                ports.forEach(port => {
                    if (port.panel && port.panel.id) {
                        const fromId = 'switch-' + s.id;
                        const toId   = 'patch_panel-' + port.panel.id;
                        // Avoid duplicate edges
                        const exists = topoEdges.find(e => e.from === fromId && e.to === toId);
                        if (!exists) {
                            topoEdges.push({ from: fromId, to: toId, label: '', color: 'rgba(245,158,11,0.5)' });
                        }
                    }
                });
            });

            // Canvas size
            const W = Math.max(totalWidth + 40, wrap.clientWidth || 900);
            const H = Math.max(START_Y * 2 + rks.reduce((m, rack) => {
                const cnt = sw.filter(s=>s.rack_id==rack.id).reduce((acc, s) => {
                    const h = (s.is_core == 1 || s.is_core === true || s.is_core === '1') ? CARD_H_SW * 3 : CARD_H_SW;
                    return acc + h + ITEM_GAP_Y;
                }, 0)
                          + pp.filter(p=>p.rack_id==rack.id).length * (CARD_H_P +ITEM_GAP_Y)
                          + fp.filter(f=>f.rack_id==rack.id).length * (CARD_H_P +ITEM_GAP_Y);
                return Math.max(m, cnt + 80);
            }, 400), 500);

            canvas.width  = W;
            canvas.height = H;
            canvas.style.width  = W + 'px';
            canvas.style.height = H + 'px';
            wrap.style.height   = '620px';

            const ctx = canvas.getContext('2d');
            ctx.clearRect(0, 0, W, H);

            // Draw rack backgrounds
            topoNodes.filter(n => n.type === 'rack').forEach(n => {
                ctx.save();
                ctx.fillStyle   = 'rgba(30,41,59,0.5)';
                ctx.strokeStyle = '#334155';
                ctx.lineWidth   = 1;
                roundRect(ctx, n.x, n.y, n.w, n.h, 12);
                ctx.fill(); ctx.stroke();
                ctx.fillStyle = '#475569';
                ctx.font = 'bold 12px Segoe UI';
                ctx.fillText(n.label, n.x + 12, n.y + 18);
                if (n.sublabel) {
                    ctx.font = '11px Segoe UI'; ctx.fillStyle = '#334155';
                    ctx.fillText(n.sublabel, n.x + 12, n.y + 33);
                }
                ctx.restore();
            });

            // Draw edges
            topoEdges.forEach(e => {
                const from = topoNodes.find(n => n.id === e.from);
                const to   = topoNodes.find(n => n.id === e.to);
                if (!from || !to) return;
                const isHighlighted = topoTracePath.includes(e.from) && topoTracePath.includes(e.to);
                ctx.save();
                ctx.strokeStyle = isHighlighted ? '#c4b5fd' : e.color;
                ctx.lineWidth   = isHighlighted ? 3 : 1.5;
                if (!isHighlighted) { ctx.setLineDash([4,3]); }
                ctx.beginPath();
                ctx.moveTo(from.x + from.w, from.y + from.h / 2);
                const midX = (from.x + from.w + to.x) / 2;
                ctx.bezierCurveTo(midX, from.y + from.h/2, midX, to.y + to.h/2, to.x, to.y + to.h/2);
                ctx.stroke();
                ctx.setLineDash([]);
                ctx.restore();
            });

            // Draw device nodes
            topoNodes.filter(n => n.type !== 'rack').forEach(n => {
                const colors  = TOPO_COLORS[n.type] || TOPO_COLORS.switch;
                const dimmed  = topoHighlight && topoHighlight !== n.id && !topoTracePath.includes(n.id);
                ctx.save();
                ctx.globalAlpha = dimmed ? 0.3 : 1;

                // Card background
                ctx.fillStyle   = colors.fill;
                ctx.strokeStyle = topoTracePath.includes(n.id) ? '#c4b5fd' : colors.stroke;
                ctx.lineWidth   = topoTracePath.includes(n.id) ? 2.5 : 1.5;
                roundRect(ctx, n.x, n.y, n.w, n.h, 8);
                ctx.fill(); ctx.stroke();

                // Icon strip
                ctx.fillStyle = colors.stroke;
                roundRect(ctx, n.x, n.y, 6, n.h, 8, true);
                ctx.fill();

                // Label
                ctx.fillStyle = colors.text;
                ctx.font = 'bold 13px Segoe UI';
                ctx.fillText(truncStr(n.label, 22), n.x + 14, n.y + 20);

                // Sublabel
                ctx.font = '11px Segoe UI'; ctx.fillStyle = '#64748b';
                ctx.fillText(n.sublabel || '', n.x + 14, n.y + 36);

                // Status dot for switches
                if (n.type === 'switch') {
                    const online = n.status === 'online';
                    ctx.beginPath();
                    ctx.arc(n.x + n.w - 14, n.y + 14, 5, 0, Math.PI*2);
                    ctx.fillStyle = online ? '#10b981' : '#ef4444';
                    ctx.fill();

                    // Mini port indicators
                    const maxPorts = Math.min(n.ports.length, 24);
                    const pW = 7, pH = 7, pGap = 2, pStartX = n.x + 14, pStartY = n.y + 48;
                    for (let i = 0; i < maxPorts; i++) {
                        const port  = n.ports[i];
                        const col   = i % 12, row = Math.floor(i / 12);
                        const px    = pStartX + col * (pW + pGap);
                        const py    = pStartY + row * (pH + pGap);
                        const active = port && (port.device || port.ip || port.mac);
                        ctx.fillStyle   = active ? '#10b981' : '#1e3a5f';
                        ctx.strokeStyle = active ? '#059669' : '#334155';
                        ctx.lineWidth   = 0.8;
                        ctx.beginPath();
                        ctx.rect(px, py, pW, pH);
                        ctx.fill(); ctx.stroke();

                        // Click target for trace mode
                        if (!dimmed) {
                            topoHitBoxes.push({ x:px, y:py, w:pW, h:pH, nodeId:n.id, portIndex:i, portData:port });
                        }
                    }
                }

                // Hitbox for the whole card
                topoHitBoxes.push({ x:n.x, y:n.y, w:n.w, h:n.h, nodeId:n.id });
                ctx.restore();
            });
        }

        // ─── Canvas click handler ─────────────────────────────────────────
        document.addEventListener('DOMContentLoaded', () => {
            const canvas = document.getElementById('topo-canvas');
            if (!canvas) return;
            canvas.addEventListener('click', (e) => {
                const rect = canvas.getBoundingClientRect();
                const mx   = e.clientX - rect.left;
                const my   = e.clientY - rect.top;
                for (const hb of topoHitBoxes) {
                    if (mx >= hb.x && mx <= hb.x + hb.w && my >= hb.y && my <= hb.y + hb.h) {
                        if (topoView === 'trace' && hb.portIndex !== undefined && hb.portData) {
                            // Trace mode: click port → trace cable path
                            tracePort(hb.nodeId, hb.portIndex, hb.portData);
                        } else if (hb.portIndex === undefined) {
                            const node = topoNodes.find(n => n.id === hb.nodeId);
                            if (node && node.type === 'switch' && node.dataId) {
                                // Click switch node → navigate to switch detail
                                const sw = (typeof switches !== 'undefined' ? switches : []).find(s => s.id == node.dataId);
                                if (sw) {
                                    showPage('switches');
                                    showSwitchDetail(sw);
                                }
                            } else {
                                topoHighlight = topoHighlight === hb.nodeId ? null : hb.nodeId;
                                topoRender();
                            }
                        }
                        break;
                    }
                }
            });

            // Cursor change on hover
            canvas.addEventListener('mousemove', (e) => {
                const rect = canvas.getBoundingClientRect();
                const mx   = e.clientX - rect.left;
                const my   = e.clientY - rect.top;
                const hit  = topoHitBoxes.find(hb => mx>=hb.x && mx<=hb.x+hb.w && my>=hb.y && my<=hb.y+hb.h);
                canvas.style.cursor = hit ? 'pointer' : 'default';
            });
        });

        function tracePort(nodeId, portIndex, portData) {
            // Build path: switch → patch panel → fiber panel (if any)
            const resultEl = document.getElementById('topo-trace-result');
            const panel    = document.getElementById('topo-trace-panel');
            const path     = [];
            const steps    = [];

            path.push(nodeId);
            const sw = topoNodes.find(n => n.id === nodeId);
            steps.push({ label: sw ? sw.label : nodeId, sub: `Port ${(portData && portData.port ? portData.port : portIndex+1)}`, color:'#3b82f6', icon:'fa-network-wired' });

            if (portData && portData.panel) {
                const panelNodeId = 'patch_panel-' + portData.panel.id;
                path.push(panelNodeId);
                const ppNode = topoNodes.find(n => n.id === panelNodeId);
                steps.push({ label: ppNode ? ppNode.label : ('Panel ' + portData.panel.letter), sub: `Port ${portData.panel.port}`, color:'#f59e0b', icon:'fa-th-large', arrow:true });
            }

            topoTracePath = path;
            topoHighlight = null;
            topoRender();

            // Render trace steps
            resultEl.innerHTML = steps.map((s, i) => `
                ${i > 0 ? '<span style="color:#c4b5fd; font-size:18px; margin:0 4px;">→</span>' : ''}
                <div style="background:rgba(139,92,246,.1); border:1px solid rgba(139,92,246,.3); border-radius:8px; padding:8px 14px; display:flex; align-items:center; gap:8px;">
                    <i class="fas ${s.icon}" style="color:${s.color};"></i>
                    <div>
                        <div style="font-weight:700; color:var(--text);">${escapeHtml(s.label)}</div>
                        <div style="font-size:11px; color:var(--text-light);">${escapeHtml(s.sub)}</div>
                    </div>
                </div>`).join('');

            panel.style.display = '';
        }

        function filterTopologyNodes(q) {
            if (!q) { topoReset(); return; }
            q = q.toLowerCase();
            const sw = (typeof switches !== 'undefined' ? switches : []);
            const pp = (typeof patchPanels !== 'undefined' ? patchPanels : []);
            topoHighlight = null;
            topoTracePath = [];
            const matched = [];
            [...sw, ...pp].forEach(item => {
                const s = JSON.stringify(item).toLowerCase();
                if (s.includes(q)) matched.push((item.panel_letter ? 'patch_panel-' : 'switch-') + item.id);
            });
            if (matched.length > 0) topoHighlight = matched[0];
            topoRender();
        }

        // ─── Canvas helpers ───────────────────────────────────────────────
        function roundRect(ctx, x, y, w, h, r, fillOnly) {
            ctx.beginPath();
            ctx.moveTo(x + r, y);
            ctx.lineTo(x + w - r, y);
            ctx.quadraticCurveTo(x + w, y, x + w, y + r);
            ctx.lineTo(x + w, y + h - r);
            ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
            ctx.lineTo(x + r, y + h);
            ctx.quadraticCurveTo(x, y + h, x, y + h - r);
            ctx.lineTo(x, y + r);
            ctx.quadraticCurveTo(x, y, x + r, y);
            ctx.closePath();
        }
        function truncStr(s, max) {
            return s && s.length > max ? s.substring(0, max) + '…' : (s || '');
        }
        
        function loadPortAlarmsPage() {
            // Port alarms page is loaded via iframe (like device-import)
            // The iframe loads port_alarms.php which handles its own display
        }

        function showSwitchDetail(sw, highlightPort) {
            selectedSwitch = sw;
            const detailPanel = document.getElementById('detail-panel');
            const rack = racks.find(r => r.id === sw.rack_id);
            const connections = portConnections[sw.id] || [];
            
            // Portları port numarasına göre sırala
            connections.sort((a, b) => a.port - b.port);
            
            // Update detail panel content
            const isCoreSw3 = sw.is_core == 1 || sw.is_core === true || sw.is_core === '1';
            document.getElementById('switch-detail-name').innerHTML = sw.name + (isCoreSw3 ? ' <span style="background:#fbbf24;color:#1e293b;font-size:0.65rem;font-weight:800;padding:2px 7px;border-radius:10px;letter-spacing:1px;vertical-align:middle;">CORE SW</span>' : '');
            document.getElementById('switch-detail-brand').textContent = `${sw.brand} ${sw.model}`;
            document.getElementById('switch-detail-status').innerHTML = 
                `<i class="fas fa-circle" style="color: ${sw.status === 'online' ? '#10b981' : '#ef4444'}"></i> ${sw.status === 'online' ? 'Çevrimiçi' : 'Çevrimdışı'}`;
            
            const activePorts = connections.filter(c => {
                // Exclude ports where the link is administratively or physically down
                if (c.is_down) return false;
                if (c.device && c.device.trim() !== '' && c.type && c.type !== 'BOŞ') return true;
                if (c.connection_info_preserved) {
                    try {
                        const p = JSON.parse(c.connection_info_preserved);
                        if (p && p.type === 'virtual_core_reverse') return true;
                    } catch(e) {}
                }
                return false;
            }).length;
            document.getElementById('switch-detail-ports').textContent = `${activePorts}/${sw.ports} Port Aktif`;

            // Fetch switch-level PoE budget (for header span) and health data (for bar)
            // using Promise.all so the PoE badge in the health bar can fall back to
            // poe.php data when snmp_switch_health.php has no poe_nominal_w (DB not yet
            // populated by Python worker or CBS350 SNMPv3 engine-id not yet discovered).
            const poeSpan = document.getElementById('switch-detail-poe');
            poeSpan.style.display = 'none';

            const _poePromise    = fetch(`api/snmp_switch_poe.php?switch_id=${sw.id}`).then(r => r.json()).catch(() => null);
            const _healthPromise = (function() {
                const bar = document.getElementById('switch-health-bar');
                if (sw.is_virtual == 1 || sw.is_virtual === true || sw.is_virtual === '1') {
                    bar.style.display = 'none';
                    return Promise.resolve(null);
                }
                bar.innerHTML = '<span id="switch-health-loading"><i class="fas fa-circle-notch fa-spin"></i> Sistem bilgileri alınıyor…</span>';
                bar.style.display = 'flex';
                return fetch(`api/snmp_switch_health.php?switch_id=${sw.id}`).then(r => r.json()).catch(() => null);
            })();

            // Header PoE span — update as soon as poe.php responds
            _poePromise.then(p => {
                if (p && p.success) {
                    const remaining = p.nominal_w - p.used_w;
                    poeSpan.innerHTML = `<i class="fas fa-bolt" style="color:#f59e0b;"></i> PoE: ${p.used_w}W kullanılan / ${remaining}W kalan`;
                    poeSpan.style.display = '';
                }
            });

            // Health bar — wait for both so the PoE badge can use whichever has data
            Promise.all([_healthPromise, _poePromise]).then(([h, poeData]) => {
                const bar = document.getElementById('switch-health-bar');
                if (!h || !h.success) {
                    if (h && h.virtual) {
                        bar.style.display = 'none';
                    } else if (!h || !h.success) {
                        bar.innerHTML = `<span style="color:#64748b;font-size:0.8rem;"><i class="fas fa-exclamation-triangle" style="color:#f59e0b;"></i> Sistem bilgisi alınamadı</span>`;
                    }
                    return;
                }

                const badges = [];

                        // System Name
                        if (h.sys_name) {
                            badges.push(`<div class="health-badge info">
                                <i class="fas fa-tag hb-icon" style="color:#38bdf8;"></i>
                                <span class="hb-label">Sistem Adı</span>
                                <span class="hb-val" style="font-size:0.85rem;">${h.sys_name}</span>
                            </div>`);
                        }

                        // System Uptime
                        if (h.sys_uptime && h.sys_uptime !== '-') {
                            badges.push(`<div class="health-badge info">
                                <i class="fas fa-clock hb-icon" style="color:#818cf8;"></i>
                                <span class="hb-label">Uptime</span>
                                <span class="hb-val" style="font-size:0.85rem;">${h.sys_uptime}</span>
                            </div>`);
                        }

                        // Model
                        if (h.model) {
                            badges.push(`<div class="health-badge info">
                                <i class="fas fa-server hb-icon" style="color:#6ee7b7;"></i>
                                <span class="hb-label">Model</span>
                                <span class="hb-val" style="font-size:0.85rem;">${h.model}</span>
                            </div>`);
                        }

                        // Temperature
                        if (h.temperature_c !== null) {
                            const tClass = h.temp_status === 'OK' ? 'ok' : (h.temp_status === 'WARNING' ? 'warn' : 'crit');
                            const tColor = h.temp_status === 'OK' ? '#10b981' : (h.temp_status === 'WARNING' ? '#f59e0b' : '#ef4444');
                            badges.push(`<div class="health-badge ${tClass}">
                                <i class="fas fa-thermometer-half hb-icon" style="color:${tColor};"></i>
                                <span class="hb-label">Sıcaklık</span>
                                <span class="hb-val" style="color:${tColor};">${h.temperature_c}°C</span>
                            </div>`);
                        }

                        // Fan Status
                        if (h.fan_status && h.fan_status !== 'N/A') {
                            const fClass = h.fan_status === 'OK' ? 'ok' : (h.fan_status === 'WARNING' ? 'warn' : 'crit');
                            const fColor = h.fan_status === 'OK' ? '#10b981' : (h.fan_status === 'WARNING' ? '#f59e0b' : '#ef4444');
                            const fIcon  = h.fan_status === 'OK' ? 'fa-fan' : 'fa-exclamation-triangle';
                            badges.push(`<div class="health-badge ${fClass}">
                                <i class="fas ${fIcon} hb-icon" style="color:${fColor};"></i>
                                <span class="hb-label">Fan</span>
                                <span class="hb-val" style="color:${fColor};">${h.fan_status}</span>
                            </div>`);
                        }

                        // CPU Load
                        if (h.cpu_load !== null && h.cpu_load !== undefined) {
                            const cClass = h.cpu_load > 85 ? 'crit' : (h.cpu_load > 60 ? 'warn' : 'ok');
                            const cColor = h.cpu_load > 85 ? '#ef4444' : (h.cpu_load > 60 ? '#f59e0b' : '#10b981');
                            badges.push(`<div class="health-badge ${cClass}">
                                <i class="fas fa-microchip hb-icon" style="color:${cColor};"></i>
                                <span class="hb-label">CPU</span>
                                <span class="hb-val" style="color:${cColor};">${h.cpu_load}%</span>
                            </div>`);
                        }

                        // RAM / Memory
                        if (h.memory_usage !== null && h.memory_usage !== undefined) {
                            const mClass = h.memory_usage > 85 ? 'crit' : (h.memory_usage > 70 ? 'warn' : 'ok');
                            const mColor = h.memory_usage > 85 ? '#ef4444' : (h.memory_usage > 70 ? '#f59e0b' : '#10b981');
                            badges.push(`<div class="health-badge ${mClass}">
                                <i class="fas fa-memory hb-icon" style="color:${mColor};"></i>
                                <span class="hb-label">RAM</span>
                                <span class="hb-val" style="color:${mColor};">${h.memory_usage}%</span>
                            </div>`);
                        }

                        // PoE Budget — prefer health API data; fall back to snmp_switch_poe.php
                        const poeNominal  = h.poe_nominal_w  ?? (poeData?.success ? poeData.nominal_w  : null);
                        const poeConsumed = h.poe_consumed_w ?? (poeData?.success ? poeData.used_w     : 0);
                        const poeUsagePct = h.poe_usage_pct  ?? (poeData?.success ? poeData.usage_pct  : null);
                        if (poeNominal !== null && poeNominal > 0) {
                            const pPct      = poeUsagePct ?? Math.round(poeConsumed / poeNominal * 100);
                            const pRemain   = poeNominal - poeConsumed;
                            const pClass    = pPct > 85 ? 'crit' : (pPct > 65 ? 'warn' : 'poe');
                            const pColor    = pPct > 85 ? '#ef4444' : (pPct > 65 ? '#f59e0b' : '#f59e0b');
                            badges.push(`<div class="health-badge ${pClass}">
                                <i class="fas fa-bolt hb-icon" style="color:${pColor};"></i>
                                <span class="hb-label">PoE</span>
                                <span class="hb-val" style="font-size:0.82rem;">${poeConsumed}W <span style="color:#64748b;font-weight:400;">kullanılan</span></span>
                                <span style="font-size:0.78rem;color:#94a3b8;">${pRemain}W kalan &nbsp;(${pPct}%)</span>
                            </div>`);
                        }

                        // PoE Aktif Port Sayacı
                        if (h.poe_active_ports !== null && h.poe_active_ports !== undefined) {
                            const paColor = h.poe_active_ports > 35 ? '#ef4444' : (h.poe_active_ports > 25 ? '#f59e0b' : (h.poe_active_ports > 0 ? '#10b981' : '#94a3b8'));
                            const paClass = h.poe_active_ports > 35 ? 'crit' : (h.poe_active_ports > 25 ? 'warn' : (h.poe_active_ports > 0 ? 'ok' : 'info'));
                            badges.push(`<div class="health-badge ${paClass}">
                                <i class="fas fa-plug hb-icon" style="color:${paColor};"></i>
                                <span class="hb-label">PoE Port</span>
                                <span class="hb-val" style="color:${paColor};">${h.poe_active_ports} <span style="color:#64748b;font-weight:400;">/ ${h.poe_total_ports}</span></span>
                            </div>`);
                        }

                        if (badges.length === 0) {
                            bar.style.display = 'none';
                        } else {
                            // DB kaynağı ise küçük bir önbellek göstergesi ekle
                            if (h.source === 'database') {
                                badges.push(`<span class="health-cache-note"><i class="fas fa-database"></i> Önbellek</span>`);
                            }
                            bar.innerHTML = badges.join('');
                        }
            }).catch(() => {
                const bar = document.getElementById('switch-health-bar');
                bar.style.display = 'none';
            });
            
            // Update rack bilgisi
            if (rack) {
                document.getElementById('switch-detail-name').innerHTML = `
                    ${sw.name}<br>
                    <small style="font-size: 0.8rem; color: var(--text-light);">
                        <i class="fas fa-server"></i> ${rack.name} - ${rack.location}
                    </small>
                `;
            }
            
            // Update 3D switch view
            document.getElementById('switch-brand-3d').textContent = sw.brand;
            document.getElementById('switch-name-3d').textContent = sw.name;
            
            // Update port indicators
            const indicators = document.getElementById('port-indicators');
            const indicatorCount = Math.min(40, sw.ports);
            
            indicators.innerHTML = '';
            const isCoreSw = (sw.is_core == 1 || sw.is_core === true || sw.is_core === '1');
            for (let i = 1; i <= indicatorCount; i++) {
                const connection = connections.find(c => c.port === i);

                // Detect virtual_core / virtual_core_reverse for green-dot determination
                let indIsVcConnected = false;
                if (connection && !connection.is_down) {
                    const ciStr = (connection.connection_info_preserved || '').trim();
                    const rfStr = connection.core_reverse_fallback || '';
                    const checkStr = (ciStr && ciStr[0] === '{') ? ciStr : rfStr;
                    if (checkStr) {
                        try {
                            const p = JSON.parse(checkStr);
                            if (p && (p.type === 'virtual_core_reverse' || p.type === 'virtual_core')) {
                                indIsVcConnected = true;
                            }
                        } catch(e) {}
                    }
                    // Also check core_connection_info (JSON or pipe format) for virtual_core
                    if (!indIsVcConnected && connection.core_connection_info) {
                        const cci = connection.core_connection_info;
                        try {
                            const cciP = JSON.parse(cci);
                            if (cciP && cciP.type === 'virtual_core') indIsVcConnected = true;
                        } catch(e) {
                            if (cci.indexOf('|') !== -1 || cci.trim()) indIsVcConnected = true;
                        }
                    }
                }

                // Show green only when port is UP and has device/mac/ip OR a virtual connection
                const isUp = connection && !connection.is_down &&
                    ((connection.device || connection.mac || connection.ip || connection.is_hub) || indIsVcConnected);
                
                const indicator = document.createElement('div');
                indicator.className = 'port-indicator';
                if (isUp) {
                    indicator.classList.add('active');
                    indicator.title = `Port ${i}: ${connection.device || connection.ip || 'UP'}`;
                } else if (connection && connection.is_down) {
                    const hasEverSeen = connection.device || connection.mac || connection.ip;
                    // All core switch ports are fiber; for edge switches only last 4 ports are fiber.
                    const isFiberPort = isCoreSw || i > (sw.ports - 4);
                    // Mirror port-grid logic: a port with no device name is treated as
                    // generic (ETHERNET) type regardless of the stored connection type.
                    const isConnectedPort = !!(connection.device && connection.device.trim() !== '' && connection.type !== 'BOŞ');
                    const connType = isConnectedPort ? (connection.type || '').toUpperCase() : 'ETHERNET';
                    const isGenericType = connType === 'ETHERNET' || connType === 'FIBER' || connType === 'BOŞ' || connType === '' || isFiberPort;
                    if (hasEverSeen && !isGenericType) {
                        indicator.classList.add('down');
                    }
                    // else: no class → default grey (never-seen equivalent)
                    indicator.title = `Port ${i}: DOWN`;
                }
                indicators.appendChild(indicator);
            }
            
            // Update port grid
            const portsGrid = document.getElementById('detail-ports-grid');
            portsGrid.innerHTML = '';
            
            // VLAN ID → display label for hub-icon badge (mirrors getData.php $vlanTypeMapPhp)
            const HUB_BADGE_VLAN_MAP = {30:'GUEST',40:'VIP',50:'DEVICE',70:'AP',80:'KAMERA',110:'SES',120:'OTOMASYON',130:'IPTV',140:'SANTRAL',150:'JACKPOT',254:'SERVER',1500:'DRGT'};

            // Port grid'i oluştur
            for (let i = 1; i <= sw.ports; i++) {
                const connection = connections.find(c => c.port === i);
                // Detect virtual_core_reverse (core switch → edge switch connection) and
                // virtual_core (edge switch → core switch connection) from connection_info_preserved.
                let isVirtualCoreReverse = false;
                let virtualCoreEdgeName = '';
                let isVirtualCore = false;
                let virtualCoreSwitchName = '';
                if (connection && connection.connection_info_preserved) {
                    try {
                        const vcRParsed = JSON.parse(connection.connection_info_preserved);
                        if (vcRParsed && vcRParsed.type === 'virtual_core_reverse') {
                            isVirtualCoreReverse = true;
                            virtualCoreEdgeName = vcRParsed.edge_switch_name || '';
                        } else if (vcRParsed && vcRParsed.type === 'virtual_core') {
                            isVirtualCore = true;
                            virtualCoreSwitchName = vcRParsed.core_switch_name || '';
                        }
                    } catch(e) {}
                }
                // Fallback: if no virtual_core_reverse JSON but snmp_core_ports has an
                // entry pointing back to this core port, use core_reverse_fallback JSON.
                if (!isVirtualCoreReverse && connection && connection.core_reverse_fallback) {
                    try {
                        const rFb = JSON.parse(connection.core_reverse_fallback);
                        if (rFb && rFb.type === 'virtual_core_reverse') {
                            isVirtualCoreReverse = true;
                            virtualCoreEdgeName = rFb.edge_switch_name || '';
                        }
                    } catch(e) {}
                }
                // Fallback: if no virtual_core JSON in connection_info_preserved but
                // snmp_core_ports recorded a core switch connection in core_connection_info,
                // use that to detect virtual_core (handles JSON-format and pipe-format storage).
                if (!isVirtualCore && !isVirtualCoreReverse && connection && connection.core_connection_info) {
                    const cci = connection.core_connection_info;
                    try {
                        const cciP = JSON.parse(cci);
                        if (cciP && cciP.type === 'virtual_core') {
                            isVirtualCore = true;
                            virtualCoreSwitchName = cciP.core_switch_name || '';
                        }
                    } catch(e) {
                        // Pipe-separated format: "CoreSW | PortLabel"
                        const pipeIdx = cci.indexOf('|');
                        if (pipeIdx !== -1) {
                            isVirtualCore = true;
                            virtualCoreSwitchName = cci.substring(0, pipeIdx).trim();
                        } else if (cci.trim()) {
                            isVirtualCore = true;
                            virtualCoreSwitchName = cci.trim();
                        }
                    }
                }
                const isConnected = (connection && connection.device && connection.device.trim() !== '' && connection.type !== 'BOŞ') || isVirtualCoreReverse || isVirtualCore;
                const isHub = connection && connection.is_hub == 1;
                const hasConnection = (connection && connection.connection_info && connection.connection_info !== '[]' && connection.connection_info !== 'null') ||
                    (connection && connection.connection_info_preserved && connection.connection_info_preserved !== '' && connection.connection_info_preserved !== 'null');
                const isDown = connection && connection.is_down;
                // "VLAN X" type: port is up but VLAN is unrecognized
                const isVlanType = connection && connection.type && /^VLAN \d+$/.test(connection.type);
                
                const portItem = document.createElement('div');
                portItem.className = `port-item`;
                
                if (isConnected) {
                    portItem.classList.add('connected');
                    if (isHub) {
                        portItem.classList.add('hub');
                    } else if (isVirtualCoreReverse || isVirtualCore) {
                        portItem.classList.add('fiber');
                    } else {
                        // Derive CSS class: "VLAN 30" → "vlan", others use lowercase type
                        const typeClass = isVlanType ? 'vlan' : (connection.type?.toLowerCase() || 'device');
                        portItem.classList.add(typeClass);
                    }
                }
                // Also mark VLAN-type UP ports with the vlan class (red)
                if (isVlanType && !isDown) {
                    portItem.classList.add('connected');
                    portItem.classList.add('vlan');
                }
                // Core switch: mark empty ports with red border to show they have no connection
                if ((sw.is_core == 1 || sw.is_core === true || sw.is_core === '1') && !isConnected && !isDown) {
                    portItem.classList.add('down');
                }
                
                portItem.dataset.port = i;
                
                let portType = 'BOŞ';
                let deviceName = '';
                let rackPort = '';
                let isFiber = (sw.is_core == 1 || sw.is_core === true || sw.is_core === '1') ? true : i > (sw.ports - 4); // Core SW portların hepsi fiber, diğerlerinde son 4 port fiber
                let hubBadgeLabel = 'H'; // hub-icon badge: default 'H', overridden to VLAN name below

                // For virtual_core_reverse ports: set deviceName and portType from parsed JSON
                if (isVirtualCoreReverse) {
                    deviceName = virtualCoreEdgeName;
                    if (deviceName && deviceName.length > 12) deviceName = deviceName.substring(0, 12) + '...';
                    portType = 'FIBER';
                } else if (isVirtualCore) {
                    // Edge switch uplink port: show abbreviated core switch name + FIBER type
                    deviceName = unwrapCoreSwitchName(virtualCoreSwitchName);
                    if (deviceName && deviceName.length > 12) deviceName = deviceName.substring(0, 12) + '...';
                    portType = 'FIBER';
                }
                
                if ((isConnected && !isVirtualCoreReverse && !isVirtualCore) || isVlanType) {
                    if (isHub) {
                        // Hub-icon badge always says "HUB"
                        hubBadgeLabel = 'HUB';

                        // Port-type badge: show VLAN type name (e.g. JACKPOT) when known, else "HUB"
                        const vlanId = connection && connection.snmp_vlan_id ? parseInt(connection.snmp_vlan_id) : 0;
                        portType = (vlanId && HUB_BADGE_VLAN_MAP[vlanId]) ? HUB_BADGE_VLAN_MAP[vlanId] : 'HUB';

                        deviceName = connection.hub_name || 'Hub Port';
                        
                        // Show device count without "Hub" prefix – just "N port"
                        if (connection.device_count > 0) {
                            deviceName = `${connection.device_count} port`;
                        } else if (connection.ip_count > 1 || connection.mac_count > 1) {
                            const deviceCount = Math.max(connection.ip_count || 0, connection.mac_count || 0);
                            deviceName = `${deviceCount} port`;
                        }
                    } else {
                        portType = connection.type || 'DEVICE';
                        deviceName = connection.device || '';
                    }
                    
                    if (deviceName && deviceName.length > 12) {
                        deviceName = deviceName.substring(0, 12) + '...';
                    }
                    if (connection.rack_port && connection.rack_port > 0) {
                        rackPort = `R:${connection.rack_port}`;
                    }
                } else {
                    portType = isFiber ? 'FIBER' : 'ETHERNET';
                }

                // Mark DOWN ports: red border if a device/MAC/IP was ever seen on a named-service port,
                // grey (never-seen) for ETHERNET/FIBER type ports (no specific service assigned)
                if (isDown) {
                    const hasEverSeen = connection && (connection.device || connection.mac || connection.ip);
                    const isGenericType = portType === 'ETHERNET' || portType === 'FIBER';
                    portItem.classList.add((hasEverSeen && !isGenericType) ? 'down' : 'never-seen');
                }

                // Mark ports with active alarms: yellow/amber border (overrides down/never-seen)
                if (window._portAlarmsMap && window._portAlarmsMap[`${sw.id}:${i}`]) {
                    portItem.classList.add('has-alarm');
                }

                // For DOWN ETHERNET/DEVICE ports: if still no deviceName but we have a
                // known VLAN, show the VLAN type label so the port is identifiable.
                // Only append the raw VLAN ID suffix when portType is generic (not already
                // a named VLAN type like "IPTV") – avoids confusing badge text like "IPTV ↓ 2116".
                const namedVlanTypes = new Set(Object.values(HUB_BADGE_VLAN_MAP).map(v => v.toUpperCase()));
                let vlanSuffix = '';
                if (isDown && connection && connection.snmp_vlan_id > 1) {
                    const downVlanId = parseInt(connection.snmp_vlan_id);
                    // Only append VLAN ID when portType doesn't already encode the VLAN name
                    if (!namedVlanTypes.has(portType.toUpperCase())) {
                        vlanSuffix = ` ${downVlanId}`;
                    }
                    // Do NOT use HUB_BADGE_VLAN_MAP to populate deviceName for DOWN ports:
                    // doing so caused VLAN-based labels (AP, DEVICE, TV…) to reappear
                    // on every port after a "boşa çek" (reset), making the reset look
                    // ineffective.  The VLAN ID is still appended to the badge (vlanSuffix).
                }
                
                // CSS class for port-type badge: hub ports always use 'hub' (orange) regardless of
                // displayed VLAN type name; "VLAN X" unrecognized → 'vlan'; others lowercase
                const portTypeCss = isHub ? 'hub' : (isVlanType ? 'vlan' : portType.toLowerCase());

                // SNMP port alias (ifAlias) display logic:
                // - Connected port with real device name → show alias as subtitle (if different)
                // - Connected port with purely numeric device name → promote alias to primary label
                // - Port with NO real device name (empty after reset or never-set) → show alias
                //   with "(Alias)" tag so it's clear the label is switch-configured, not a hostname
                const rawAlias = connection && connection.snmp_port_alias ? connection.snmp_port_alias : '';
                // When device name is purely numeric, prefer the alias as the primary display name
                const _isPureNumDev = /^\d+$/.test(deviceName);
                let _cardDevName;
                if (deviceName) {
                    _cardDevName = (_isPureNumDev && rawAlias) ? rawAlias : deviceName;
                } else if (rawAlias) {
                    // No real device name: show alias directly as the card label
                    _cardDevName = rawAlias;
                } else {
                    _cardDevName = '';
                }
                // Show alias as subtitle only when connected and alias differs from the device name
                const portAlias = (rawAlias && deviceName && rawAlias !== deviceName && isConnected) ? rawAlias : '';
                // Escape for safe HTML injection (escapeHtml is inside the tooltip IIFE)
                const safeAlias = portAlias ? portAlias.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;') : '';
                const safeCardDev = _cardDevName ? _cardDevName.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;') : '';

                // Core switch: compute port label from switch name suffix (CORESW-1 → slot 1, CORESW-2 → slot 2)
                // Each core switch has 2 modules × 48 ports: ports 1-48 → module 1, ports 49-96 → module 2
                const isCoreSw2 = sw.is_core == 1 || sw.is_core === true || sw.is_core === '1';
                let portNumDisplay = String(i);
                let portLabel = '';
                if (isCoreSw2) {
                    const nameSlotMatch = sw.name ? sw.name.match(/-(\d+)$/) : null;
                    const slot = nameSlotMatch ? parseInt(nameSlotMatch[1], 10) : 1;
                    const coreModule = i <= 48 ? 1 : 2;
                    const corePortWithin = ((i - 1) % 48) + 1;
                    portNumDisplay = `Tw${slot}/${coreModule}/0/${corePortWithin}`;
                    portLabel = `TwentyFiveGigE${slot}/${coreModule}/0/${corePortWithin}`;
                }

const isPoeActive = connection && connection.snmp_poe_detecting == 1;
const poePowerMw = isPoeActive && connection.snmp_poe_power_mw ? parseInt(connection.snmp_poe_power_mw) : 0;
const poeTipText = isPoeActive ? (poePowerMw > 0 ? `PoE: ${(poePowerMw/1000).toFixed(1)}W` : 'PoE Aktif') : '';

portItem.innerHTML = `
    <div class="port-number" style="${isCoreSw2 ? 'font-size:0.6rem;' : ''}">${portNumDisplay}</div>
    <div class="port-type ${portTypeCss}">${portType}${isDown ? ' ↓' : ''}${vlanSuffix}</div>
    ${safeAlias ? `<div class="port-alias" title="${safeAlias}">${safeAlias}</div>` : ''}
    <div class="port-device">${safeCardDev}</div>
    ${rackPort ? `<div class="port-rack">${rackPort}</div>` : ''}
    ${isHub ? `<div class="hub-icon">${hubBadgeLabel}</div>` : ''}
    ${isPoeActive ? `<div class="poe-badge"><i class="fas fa-bolt"></i></div>` : ''}
    ${hasConnection ? '<div class="connection-indicator" title="Bağlantı Detayı"><i class="fas fa-link"></i></div>' : ''}
`;

// ---
// add data-* attributes for tooltip and logic
if (connection) {
    // connection may contain: connection_info_preserved, connection_info, multiple_connections
    const connPreserved = connection.connection_info_preserved || '';
    const connJson = connection.connection_info || connection.multiple_connections || '';

    // For the data-connection attribute: prefer the real connection_info_preserved JSON.
    // Fallback chain: core_reverse_fallback (for CORESW ports) → raw connPreserved text
    const effectiveConnPreserved = (() => {
        if (connPreserved && connPreserved.trim().startsWith('{')) return connPreserved;
        if (connection.core_reverse_fallback) return connection.core_reverse_fallback;
        return connPreserved;
    })();

    if (effectiveConnPreserved) {
        portItem.setAttribute('data-connection', effectiveConnPreserved);
    } else {
        portItem.removeAttribute('data-connection');
    }

    if (connection.multiple_connections) {
        // Augment multiple_connections with any extra MACs from the raw mac column
        // so the tooltip shows the same devices as the hub popup.
        let augmentedDevices = [];
        try { augmentedDevices = JSON.parse(connection.multiple_connections); } catch(e) {}
        if (connection.mac) {
            const rawMacs = connection.mac.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
            const registeredMacs = new Set(augmentedDevices.map(d => (d.mac || '').trim().toUpperCase()).filter(Boolean));
            rawMacs.forEach(mac => {
                if (!registeredMacs.has(mac)) {
                    // Prefer filling the MAC into an existing entry that has a hostname
                    // but no MAC, rather than creating a second row for the same device.
                    const emptyMacEntry = augmentedDevices.find(
                        d => !d.mac && d.device && !/^Cihaz\s+\d+$/i.test(d.device)
                    );
                    if (emptyMacEntry) {
                        emptyMacEntry.mac = mac;
                    } else {
                        augmentedDevices.push({ device: `Cihaz ${augmentedDevices.length + 1}`, ip: '', mac: mac, type: 'DEVICE' });
                    }
                }
            });
        }
        portItem.setAttribute('data-multiple', JSON.stringify(augmentedDevices));
    } else if (connection.mac || connection.ip) {
        // Build placeholder list from raw MAC/IP data so the tooltip shows connected
        // devices even before the hub modal's async enrichment has run.
        const ips  = (connection.ip  || '').split(',').map(s => s.trim()).filter(Boolean);
        const macs = (connection.mac || '').split(',').map(s => s.trim()).filter(Boolean);
        const len  = Math.max(ips.length, macs.length);
        const fallbackDevices = [];
        for (let k = 0; k < len; k++) {
            fallbackDevices.push({ device: `Cihaz ${k + 1}`, ip: ips[k] || '', mac: macs[k] || '', type: 'DEVICE' });
        }
        if (fallbackDevices.length > 0) {
            portItem.setAttribute('data-multiple', JSON.stringify(fallbackDevices));
        } else {
            portItem.removeAttribute('data-multiple');
        }
    } else {
        portItem.removeAttribute('data-multiple');
    }

    if (connJson && !connection.multiple_connections) {
        // if there's a connection_info JSON (not multiple_connections), keep it too
        portItem.setAttribute('data-connection-json', connJson);
    } else {
        portItem.removeAttribute('data-connection-json');
    }
} else {
    // ensure attributes cleared for empty port
    portItem.removeAttribute('data-connection');
    portItem.removeAttribute('data-multiple');
    portItem.removeAttribute('data-connection-json');
}

// basic attributes for tooltip/search
portItem.setAttribute('data-port', i);
portItem.setAttribute('data-device', connection && connection.device ? connection.device : '');
portItem.setAttribute('data-type', connection && connection.type ? connection.type : (isFiber ? 'FIBER' : 'ETHERNET'));
portItem.setAttribute('data-ip', connection && connection.ip ? connection.ip : '');
portItem.setAttribute('data-mac', connection && connection.mac ? connection.mac : '');
portItem.setAttribute('data-port-alias', rawAlias);
portItem.setAttribute('data-port-label', portLabel || '');
// Panel bilgileri – tooltip ve port detay modalı için
portItem.setAttribute('data-panel-id',     connection && connection.connected_panel_id   ? connection.connected_panel_id   : '');
portItem.setAttribute('data-panel-port',   connection && connection.connected_panel_port ? connection.connected_panel_port : '');
portItem.setAttribute('data-panel-letter', connection && connection.connected_panel_letter ? connection.connected_panel_letter : '');
portItem.setAttribute('data-panel-rack',   connection && connection.connected_panel_rack  ? connection.connected_panel_rack  : '');
portItem.setAttribute('data-switch-id',    sw.id);
portItem.setAttribute('data-snmp-vlan',    connection && connection.snmp_vlan_id ? connection.snmp_vlan_id : '');
portItem.setAttribute('data-vlan',         connection && connection.snmp_vlan_id ? connection.snmp_vlan_id : '');
// Fallback core switch connection info: used when connection_info_preserved has
// no valid JSON (e.g. raw LLDP text "Te1/1/2") so the tooltip still shows the
// correct CORESW connection point from snmp_core_ports.
if (connection && connection.core_connection_info) {
    portItem.setAttribute('data-core-conn', connection.core_connection_info);
} else {
    portItem.removeAttribute('data-core-conn');
}

// Hub portları için özel işlemler
if (isHub) {
    // Hub ikonu için event listener
    const hubIcon = portItem.querySelector('.hub-icon');
    if (hubIcon) {
        hubIcon.addEventListener('click', function(e) {
            e.stopPropagation();
            // Hub detaylarını göster
            showHubDetails(sw.id, i, connection);
        });
    }
    
    // Port'a tıklama - sadece hub detayı göster
    portItem.addEventListener('click', function(e) {
        if (!e.target.closest('.hub-icon') && !e.target.closest('.connection-indicator')) {
            showHubDetails(sw.id, i, connection);
        }
    });
    
    // Hover efekti
    portItem.style.borderColor = '#f59e0b';
    portItem.style.background = 'linear-gradient(135deg, rgba(245, 158, 11, 0.2) 0%, rgba(245, 158, 11, 0.1) 100%)';
} else {
    // Normal port click → SNMP detay modalı
    portItem.addEventListener('click', function(e) {
        if (!e.target.closest('.connection-indicator')) {
            openSnmpPortDetailModal(sw.id, i);
        }
    });
    portItem.style.cursor = 'pointer';
}
            portsGrid.appendChild(portItem);
            }

        // Show detail panel
        detailPanel.style.display = 'block';
        detailPanel.scrollIntoView({ behavior: 'smooth' });

        // Highlight and blink a specific port if requested (e.g. clicked from card port strip)
        if (highlightPort) {
            setTimeout(() => {
                const portEl = document.querySelector(`#detail-ports-grid .port-item[data-port="${highlightPort}"]`);
                if (portEl) {
                    portEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    portEl.style.animation = 'none';
                    void portEl.offsetWidth; // reflow to restart animation
                    portEl.style.animation = 'port-highlight-blink 1s ease-in-out 4';
                }
            }, 500);
        }

        // Tooltip'leri attach et
        setTimeout(() => {
            attachPortHoverTooltips('#detail-ports-grid .port-item');
        }, 100);
        }

        function hideDetailPanel() {
            const detailPanel = document.getElementById('detail-panel');
            detailPanel.style.display = 'none';
            detailPanel.classList.remove('from-reports');
            selectedSwitch = null;
        }

        // ─── SNMP Port Detay Modalı ───────────────────────────────────
        function openSnmpPortDetailModal(switchId, portNum) {
            const modal = document.getElementById('snmp-port-detail-modal');
            const title = document.getElementById('snmp-port-detail-title');
            const subtitle = document.getElementById('snmp-port-detail-subtitle');
            const content = document.getElementById('snmp-port-detail-content');

            const sw = switches.find(s => s.id == switchId);
            title.innerHTML = `<i class="fas fa-network-wired"></i> GE${portNum} Detayları`;
            subtitle.textContent = sw ? sw.name : '';
            content.innerHTML = `<div style="text-align:center;padding:40px;"><i class="fas fa-spinner fa-spin" style="font-size:2rem;color:var(--primary);"></i><div style="margin-top:12px;color:var(--text-light);">SNMP verisi çekiliyor...</div></div>`;
            modal.classList.add('active');

            const _snmpAbortCtrl = new AbortController();
            const _snmpTimer = setTimeout(() => _snmpAbortCtrl.abort(), 20000); // 20s max
            fetch('api/snmp_port_detail.php', {
                method: 'POST',
                headers: {'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
                body: JSON.stringify({switch_id: switchId, port: portNum}),
                signal: _snmpAbortCtrl.signal
            })
            .then(r => { clearTimeout(_snmpTimer); return r.json(); })
            .then(d => {
                if (!d.success) {
                    content.innerHTML = `<div style="text-align:center;padding:40px;color:#ef4444;"><i class="fas fa-exclamation-circle fa-2x"></i><div style="margin-top:12px;">${escapeHtml(d.error || 'SNMP verisi alınamadı')}</div></div>`;
                    return;
                }
                // Virtual switch port: show connection info from DB (no live SNMP)
                if (d.virtual) {
                    const ci = d.connection_info || {};
                    const isUp = d.durum && d.durum.oper === 'up';
                    const isDown = d.durum && d.durum.oper === 'down';
                    const statusColor = isDown ? '#ef4444' : (isUp ? '#10b981' : '#94a3b8');
                    const statusLabel = isDown ? 'Bağlantı Yok' : (isUp ? 'Aktif' : 'Bilinmiyor');
                    let connRows = '';
                    let goToPortBtn = '';
                    if (ci.type === 'virtual_core_reverse' || (ci.edge_switch_name || ci.edge_port_no)) {
                        connRows += `<div class="snmp-row"><span class="snmp-label" style="color:#34d399;"><i class="fas fa-network-wired"></i> Edge SW</span><span class="snmp-value" style="color:#34d399;">${escapeHtml(ci.edge_switch_name || '')}</span></div>`;
                        connRows += `<div class="snmp-row"><span class="snmp-label">Port</span><span class="snmp-value">${escapeHtml(String(ci.edge_port_no || ''))}</span></div>`;
                        // "Porta Git" button — navigate to the edge switch and open that port's detail
                        const _edgeSwName = (ci.edge_switch_name || '').replace(/'/g, "\\'");
                        const _edgePortNo = parseInt(ci.edge_port_no) || 0;
                        if (_edgeSwName && _edgePortNo) {
                            goToPortBtn = `<div style="display:flex;justify-content:flex-end;margin-top:14px;">
                                <button class="btn btn-sm" style="background:linear-gradient(135deg,#059669,#047857);color:#fff;border:none;padding:7px 16px;border-radius:8px;cursor:pointer;font-weight:600;gap:6px;display:flex;align-items:center;"
                                    onclick="(function(){
                                        const _esw = switches.find(s => s.name === '${_edgeSwName}');
                                        document.getElementById('snmp-port-detail-modal').classList.remove('active');
                                        if (_esw) {
                                            showSwitchDetail(_esw);
                                            setTimeout(() => openSnmpPortDetailModal(_esw.id, ${_edgePortNo}), 400);
                                        }
                                    })()">
                                    <i class="fas fa-arrow-right"></i> Porta Git
                                </button>
                            </div>`;
                        }
                    } else if (d.device || d.ip || d.mac) {
                        // No virtual_core JSON – show plain device info returned from DB
                        if (d.device) connRows += `<div class="snmp-row"><span class="snmp-label">Cihaz</span><span class="snmp-value">${escapeHtml(d.device)}</span></div>`;
                        if (d.type && d.type !== 'BOŞ') connRows += `<div class="snmp-row"><span class="snmp-label">Tip</span><span class="snmp-value">${escapeHtml(d.type)}</span></div>`;
                        if (d.ip) connRows += `<div class="snmp-row"><span class="snmp-label">IP</span><span class="snmp-value" style="font-family:monospace">${escapeHtml(d.ip.split(',')[0].trim())}</span></div>`;
                        if (d.mac) connRows += `<div class="snmp-row"><span class="snmp-label">MAC</span><span class="snmp-value" style="font-family:monospace;font-size:0.8rem">${escapeHtml(d.mac.split(',')[0].trim())}</span></div>`;
                    }
                    content.innerHTML = `
                        <div class="snmp-section">
                            <div class="snmp-section-title"><i class="fas fa-plug"></i> Port Durumu</div>
                            <div class="snmp-row">
                                <span class="snmp-label">Durum</span>
                                <span class="snmp-value" style="color:${statusColor};font-weight:bold;">${statusLabel}</span>
                            </div>
                        </div>
                        ${connRows ? `<div class="snmp-section"><div class="snmp-section-title"><i class="fas fa-link"></i> Mevcut Bağlantı</div><div class="snmp-grid">${connRows}</div>${goToPortBtn}</div>` : ''}
                    `;
                    return;
                }
                const totalPorts = sw ? (parseInt(sw.ports) || 28) : 28;
                const isFiber = portNum > (totalPorts - 4);
                const isUp = d.durum.oper === 'up';
                const isUnknown = d.durum.oper === 'unknown';
                const statusColor = isUp ? '#10b981' : (isUnknown ? '#94a3b8' : '#ef4444');

                // Port item from patchPanels
                const portEl = document.querySelector(`#detail-ports-grid .port-item[data-port="${portNum}"]`);
                const panelId     = portEl ? portEl.getAttribute('data-panel-id')     : '';
                const panelPort   = portEl ? portEl.getAttribute('data-panel-port')   : '';
                const panelLetter = portEl ? portEl.getAttribute('data-panel-letter') : '';
                const panelRack   = portEl ? portEl.getAttribute('data-panel-rack')   : '';
                const panelType   = portEl ? (portEl.getAttribute('data-type') === 'FIBER' ? 'fiber' : 'patch') : 'patch';
                const snmpVlan    = portEl ? portEl.getAttribute('data-snmp-vlan') : '';

                // "Mevcut Bağlantı" data from the port element
                const connDevice  = portEl ? (portEl.getAttribute('data-device') || '') : '';
                const connIp      = portEl ? (portEl.getAttribute('data-ip')     || '') : '';
                const connMac     = portEl ? (portEl.getAttribute('data-mac')    || '') : '';
                const connMulti   = portEl ? (portEl.getAttribute('data-multiple') || '') : '';
                const connDataStr = portEl ? (portEl.getAttribute('data-connection') || '') : '';

                // Detect virtual core switch connection in data-connection attribute
                let virtualCoreInfo = null;
                let virtualCoreReverseInfo = null;
                if (connDataStr) {
                    try {
                        const vcTest = JSON.parse(connDataStr);
                        if (vcTest && vcTest.type === 'virtual_core') {
                            virtualCoreInfo = vcTest;
                        } else if (vcTest && vcTest.type === 'virtual_core_reverse') {
                            virtualCoreReverseInfo = vcTest;
                        }
                    } catch(e) { /* not JSON or not virtual_core */ }
                }

                // Build "Mevcut Bağlantı" inner rows
                let connRows = '';
                // Virtual core switch has priority over normal device data
                if (virtualCoreInfo) {
                    connRows += `<div class="snmp-row">
                        <span class="snmp-label" style="color:#fbbf24;"><i class="fas fa-server"></i> Core SW</span>
                        <span class="snmp-value" style="color:#fbbf24;">${escapeHtml(virtualCoreInfo.core_switch_name)}</span>
                    </div>`;
                    connRows += `<div class="snmp-row">
                        <span class="snmp-label">Port</span>
                        <span class="snmp-value">${escapeHtml(virtualCoreInfo.core_port_label || '')}</span>
                    </div>`;
                } else if (virtualCoreReverseInfo) {
                    connRows += `<div class="snmp-row">
                        <span class="snmp-label" style="color:#34d399;"><i class="fas fa-network-wired"></i> Edge SW</span>
                        <span class="snmp-value" style="color:#34d399;">${escapeHtml(virtualCoreReverseInfo.edge_switch_name || '')}</span>
                    </div>`;
                    connRows += `<div class="snmp-row">
                        <span class="snmp-label">Port</span>
                        <span class="snmp-value">${escapeHtml(String(virtualCoreReverseInfo.edge_port_no || ''))}</span>
                    </div>`;
                } else if (connMulti) {
                    try {
                        const arr = JSON.parse(connMulti);
                        if (Array.isArray(arr) && arr.length > 0) {
                            arr.slice(0, 6).forEach((it, idx) => {
                                const rawName = (it.device || it.name || '').trim();
                                const isGeneric = rawName === '' || /^Cihaz\s+\d+$/i.test(rawName);
                                // Use IP as hostname when no real name stored
                                const displayName = isGeneric
                                    ? (it.ip || it.mac || rawName || `Cihaz ${idx+1}`)
                                    : rawName;
                                // Suppress MAC: field when it equals the display name (avoids duplication)
                                const macUpper  = it.mac ? it.mac.toUpperCase() : '';
                                const nameUpper = displayName.toUpperCase();
                                const macIsSameName = macUpper && macUpper === nameUpper;
                                connRows += `<div class="snmp-row" style="flex-direction:column;align-items:flex-start;gap:2px;padding:8px 10px;">`;
                                connRows += `<span class="snmp-value" style="font-size:0.82rem;color:${isGeneric?'#94a3b8':'#e2e8f0'};">${escapeHtml(displayName)}</span>`;
                                if (it.ip) {
                                    connRows += `<span style="font-family:monospace;font-size:0.78rem;color:#7dd3fc;">IP: ${escapeHtml(it.ip)}</span>`;
                                } else if (!isGeneric) {
                                    // Named device with no IP → show placeholder so layout matches devices that have IPs
                                    connRows += `<span style="font-family:monospace;font-size:0.78rem;color:var(--text-light);">IP: —</span>`;
                                }
                                if (it.mac && !macIsSameName) connRows += `<span style="font-family:monospace;font-size:0.75rem;color:#64748b;">MAC: ${escapeHtml(it.mac)}</span>`;
                                connRows += `</div>`;
                            });
                        }
                    } catch(e) { /* ignore */ }
                }
                if (!connRows) {
                    if (connDevice) connRows += `<div class="snmp-row"><span class="snmp-label">Hostname</span><span class="snmp-value">${escapeHtml(connDevice)}</span></div>`;
                    if (connIp)     connRows += `<div class="snmp-row"><span class="snmp-label">IP</span><span class="snmp-value" style="font-family:monospace">${escapeHtml(connIp.split(',')[0].trim())}</span></div>`;
                    else if (connDevice) connRows += `<div class="snmp-row"><span class="snmp-label">IP</span><span class="snmp-value" style="font-family:monospace;color:var(--text-light);">—</span></div>`;
                    if (connMac)    connRows += `<div class="snmp-row"><span class="snmp-label">MAC</span><span class="snmp-value" style="font-family:monospace;font-size:0.8rem">${escapeHtml(connMac.split(',')[0].trim())}</span></div>`;
                }

                // Build side-by-side section: Panel Detayı (left) + Mevcut Bağlantı (right)
                let panelHtml = '';
                if (panelId || connRows.trim()) {
                    const leftCol = panelId ? `
                        <div style="flex:1;min-width:0;">
                            <div class="snmp-section-title" style="margin-bottom:8px;"><i class="fas fa-th-large" style="color:#8b5cf6;"></i> Panel Detayı</div>
                            <div class="snmp-grid">
                                <div class="snmp-row"><span class="snmp-label">Panel Tipi</span><span class="snmp-value">${panelType === 'fiber' ? 'Fiber Panel' : 'Patch Panel'}</span></div>
                                <div class="snmp-row"><span class="snmp-label">Panel</span><span class="snmp-value">${escapeHtml(panelLetter || panelId)}</span></div>
                                <div class="snmp-row"><span class="snmp-label">Port</span><span class="snmp-value">${panelPort}</span></div>
                                ${panelRack ? `<div class="snmp-row"><span class="snmp-label">Rack</span><span class="snmp-value">${escapeHtml(panelRack)}</span></div>` : ''}
                            </div>
                            <button class="btn btn-sm" style="margin-top:10px;background:rgba(139,92,246,0.2);border:1px solid rgba(139,92,246,0.4);color:#c4b5fd;"
                                onclick="showPanelDetail(${parseInt(panelId)||0},'${panelType === 'fiber' ? 'fiber' : 'patch'}');document.getElementById('snmp-port-detail-modal').classList.remove('active');">
                                <i class="fas fa-external-link-alt"></i> Panel Detayını Aç
                            </button>
                        </div>` : '';

                    const rightCol = connRows.trim() ? `
                        <div style="flex:1;min-width:0;">
                            <div class="snmp-section-title" style="margin-bottom:8px;"><i class="fas fa-link" style="color:#10b981;"></i> Mevcut Bağlantı</div>
                            <div class="snmp-grid">${connRows}</div>
                        </div>` : '';

                    // If only one column has content, display it full-width;
                    // otherwise show them side by side with a thin divider.
                    const bothPresent = leftCol && rightCol;
                    panelHtml = `
                    <div class="snmp-section" style="display:flex;gap:16px;flex-wrap:wrap;">
                        ${leftCol}
                        ${bothPresent ? `<div style="width:1px;background:rgba(56,189,248,0.15);flex-shrink:0;"></div>` : ''}
                        ${rightCol}
                    </div>`;
                }

                const vlanHtml = snmpVlan && snmpVlan > 1 ? `<span style="background:rgba(59,130,246,0.2);border:1px solid rgba(59,130,246,0.4);color:#93c5fd;padding:2px 8px;border-radius:12px;font-size:0.75rem;">VLAN ${snmpVlan}</span>` : '';

                let tabsHtml = `<div class="snmp-tabs" id="snmp-detail-tabs">
                    <button class="snmp-tab active" data-tab="temel">Temel</button>
                    <button class="snmp-tab" data-tab="durum">Durum</button>
                    <button class="snmp-tab" data-tab="vlan">VLAN</button>
                    ${!isFiber ? '<button class="snmp-tab" data-tab="poe">PoE</button>' : ''}
                    <button class="snmp-tab" data-tab="lldp">LLDP Komşu</button>
                    <button class="snmp-tab" data-tab="trafik">Trafik</button>
                </div>`;

                const temelHtml = `<div class="snmp-tab-content" data-content="temel">
                    <div class="snmp-grid">
                        <div class="snmp-row"><span class="snmp-label">Açıklama</span><span class="snmp-value">${escapeHtml(d.temel.descr)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Ad</span><span class="snmp-value">${escapeHtml(d.temel.name)}</span></div>
                        ${d.temel.alias ? `<div class="snmp-row"><span class="snmp-label">Alias</span><span class="snmp-value">${escapeHtml(d.temel.alias)}</span></div>` : ''}
                        <div class="snmp-row"><span class="snmp-label">Hız</span><span class="snmp-value">${escapeHtml(d.temel.speed)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">MTU</span><span class="snmp-value">${d.temel.mtu}</span></div>
                        <div class="snmp-row"><span class="snmp-label">MAC</span><span class="snmp-value" style="font-family:monospace">${escapeHtml(d.temel.mac) || '-'}</span></div>
                    </div>
                </div>`;

                const durumHtml = `<div class="snmp-tab-content" data-content="durum" style="display:none;">
                    <div class="snmp-grid">
                        <div class="snmp-row"><span class="snmp-label">Admin</span><span class="snmp-value" style="color:${d.durum.admin==='up'?'#10b981':(d.durum.admin==='unknown'?'#94a3b8':'#ef4444')}">${d.durum.admin.toUpperCase()}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Oper</span><span class="snmp-value" style="color:${d.durum.oper==='up'?'#10b981':(d.durum.oper==='unknown'?'#94a3b8':'#ef4444')}">${d.durum.oper.toUpperCase()}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Son Değişim</span><span class="snmp-value">${escapeHtml(d.durum.last_change)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Duplex</span><span class="snmp-value">${escapeHtml(d.durum.duplex)}</span></div>
                    </div>
                </div>`;

                const vlanContentHtml = `<div class="snmp-tab-content" data-content="vlan" style="display:none;">
                    <div class="snmp-grid">
                        <div class="snmp-row"><span class="snmp-label">Birincil VLAN</span><span class="snmp-value">${d.vlan.primary}</span></div>
                        <div class="snmp-row"><span class="snmp-label">PVID</span><span class="snmp-value">${d.vlan.pvid}</span></div>
                        ${d.vlan.vm_vlan > 0 ? `<div class="snmp-row"><span class="snmp-label">vmVlan</span><span class="snmp-value">${d.vlan.vm_vlan}</span></div>` : ''}
                        <div class="snmp-row"><span class="snmp-label">Üye VLAN'lar</span><span class="snmp-value">${d.vlan.vlans.join(', ') || '-'}</span></div>
                    </div>
                </div>`;

                const poeHtml = (!isFiber && d.poe) ? `<div class="snmp-tab-content" data-content="poe" style="display:none;">
                    <div class="snmp-grid">
                        ${d.poe.no_data
                            ? `<div class="snmp-row" style="grid-column:1/-1;color:#64748b;text-align:center;padding:20px;">
                                <i class="fas fa-plug" style="font-size:1.5rem;margin-bottom:8px;display:block;"></i>
                                PoE verisi alınamadı (SNMP bağlantısı yok)</div>`
                            : `<div class="snmp-row"><span class="snmp-label">Durum</span><span class="snmp-value" style="color:${d.poe.enabled===true?'#10b981':(d.poe.fault?'#f59e0b':'#94a3b8')}">${d.poe.enabled===true ? 'Aktif (Güç Veriyor)' : (d.poe.fault ? 'Güç Vermiyor' : (d.poe.enabled===false ? 'Pasif' : 'Bilinmiyor'))}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Güç</span><span class="snmp-value">${escapeHtml(d.poe.power_watt)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Sınıf</span><span class="snmp-value">${escapeHtml(d.poe.class)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Öncelik</span><span class="snmp-value">${escapeHtml(d.poe.priority)}</span></div>`
                        }
                    </div>
                </div>` : '';

                const lldpHtml = `<div class="snmp-tab-content" data-content="lldp" style="display:none;">
                    ${d.lldp ? `<div class="snmp-grid">
                        <div class="snmp-row"><span class="snmp-label">Sistem Adı</span><span class="snmp-value">${escapeHtml(d.lldp.system_name)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Port ID</span><span class="snmp-value">${escapeHtml(d.lldp.port_id)}</span></div>
                        ${d.lldp.mgmt_ip ? `<div class="snmp-row"><span class="snmp-label">Yönetim IP</span><span class="snmp-value" style="font-family:monospace">${escapeHtml(d.lldp.mgmt_ip)}</span></div>` : ''}
                        ${d.lldp.capabilities ? `<div class="snmp-row"><span class="snmp-label">Yetenekler</span><span class="snmp-value">${escapeHtml(d.lldp.capabilities)}</span></div>` : ''}
                        ${d.lldp.source === 'db' ? `<div class="snmp-row" style="margin-top:4px;"><span class="snmp-label" style="color:#64748b;font-size:0.75rem;">Kaynak: DB (önbellek)</span></div>` : ''}
                    </div>` : '<div style="text-align:center;padding:30px;color:var(--text-light);">Bu portta LLDP komşusu bulunmuyor</div>'}
                </div>`;

                const trafikHtml = `<div class="snmp-tab-content" data-content="trafik" style="display:none;">
                    <div class="snmp-grid">
                        <div class="snmp-row"><span class="snmp-label">Gelen Trafik</span><span class="snmp-value" style="color:#10b981">${escapeHtml(d.trafik.in_bytes)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Giden Trafik</span><span class="snmp-value" style="color:#3b82f6">${escapeHtml(d.trafik.out_bytes)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Gelen Paket</span><span class="snmp-value">${d.trafik.in_ucast.toLocaleString()}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Giden Paket</span><span class="snmp-value">${d.trafik.out_ucast.toLocaleString()}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Gelen Hata</span><span class="snmp-value" style="color:${d.trafik.in_errors>0?'#ef4444':'#94a3b8'}">${d.trafik.in_errors}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Giden Hata</span><span class="snmp-value" style="color:${d.trafik.out_errors>0?'#ef4444':'#94a3b8'}">${d.trafik.out_errors}</span></div>
                        <div class="snmp-row"><span class="snmp-label">FCS Hata</span><span class="snmp-value" style="color:${d.trafik.fcs_errors>0?'#ef4444':'#94a3b8'}">${d.trafik.fcs_errors}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Drop (Gelen)</span><span class="snmp-value">${d.trafik.in_discards}</span></div>
                    </div>
                </div>`;

                const srcBadge = d.source === 'database'
                    ? `<span style="background:rgba(251,191,36,0.15);border:1px solid rgba(251,191,36,0.4);color:#fbbf24;padding:2px 8px;border-radius:12px;font-size:0.72rem;" title="PHP SNMP ulaşamadı, veritabanından okundu"><i class="fas fa-database"></i> DB</span>`
                    : '';
                const displayName = d.temel.alias || d.temel.name || d.temel.descr;
                content.innerHTML = `
                <style>
                .snmp-section{background:rgba(30,41,59,0.6);border:1px solid rgba(56,189,248,0.15);border-radius:10px;padding:15px;margin-bottom:15px;}
                .snmp-section-title{font-size:0.85rem;font-weight:700;color:var(--text-light);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:10px;display:flex;align-items:center;gap:8px;}
                .snmp-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px;}
                .snmp-tab{background:rgba(30,41,59,0.6);border:1px solid rgba(56,189,248,0.15);color:var(--text-light);padding:6px 14px;border-radius:20px;cursor:pointer;font-size:0.82rem;transition:all 0.2s;}
                .snmp-tab.active{background:rgba(59,130,246,0.3);border-color:rgba(59,130,246,0.5);color:#93c5fd;}
                .snmp-grid{display:flex;flex-direction:column;gap:4px;}
                .snmp-row{display:flex;justify-content:space-between;align-items:center;padding:6px 10px;border-radius:6px;background:rgba(15,23,42,0.4);}
                .snmp-label{color:var(--text-light);font-size:0.82rem;}
                .snmp-value{font-size:0.85rem;font-weight:600;color:var(--text);}
                .btn-sm{padding:5px 10px;font-size:0.8rem;}
                </style>
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap;">
                    <span style="font-size:1.2rem;font-weight:700;color:var(--text);">${escapeHtml(displayName)}</span>
                    <span style="background:rgba(${isUp?'16,185,129':(isUnknown?'148,163,184':'239,68,68')},0.2);border:1px solid rgba(${isUp?'16,185,129':(isUnknown?'148,163,184':'239,68,68')},0.4);color:${statusColor};padding:2px 10px;border-radius:12px;font-size:0.78rem;font-weight:700;">${isUp?'UP':(isUnknown?'?':'DOWN')}</span>
                    ${vlanHtml}
                    ${d.temel.speed && d.temel.speed !== '-' ? `<span style="background:rgba(148,163,184,0.1);border:1px solid rgba(148,163,184,0.2);color:#94a3b8;padding:2px 8px;border-radius:12px;font-size:0.75rem;">${escapeHtml(d.temel.speed)}</span>` : ''}
                    ${srcBadge}
                </div>
                ${panelHtml}
                ${tabsHtml}
                ${temelHtml}${durumHtml}${vlanContentHtml}${poeHtml}${lldpHtml}${trafikHtml}`;

                // Tab click events
                content.querySelectorAll('.snmp-tab').forEach(btn => {
                    btn.addEventListener('click', function() {
                        content.querySelectorAll('.snmp-tab').forEach(b => b.classList.remove('active'));
                        content.querySelectorAll('.snmp-tab-content').forEach(c => c.style.display = 'none');
                        this.classList.add('active');
                        const tc = content.querySelector(`.snmp-tab-content[data-content="${this.dataset.tab}"]`);
                        if (tc) tc.style.display = 'block';
                    });
                });
            })
            .catch(err => {
                clearTimeout(_snmpTimer);
                const msg = err && err.name === 'AbortError'
                    ? 'SNMP isteği zaman aşımına uğradı (20s). Cihaz yavaş yanıt veriyor.'
                    : escapeHtml(err.message || 'Failed to fetch');
                content.innerHTML = `<div style="text-align:center;padding:40px;color:#ef4444;"><i class="fas fa-exclamation-circle fa-2x"></i><div style="margin-top:12px;">${msg}</div></div>`;
            });
        }
        const _closeSnmpBtn = document.getElementById('close-snmp-port-detail-modal');
        if (_closeSnmpBtn) {
            _closeSnmpBtn.addEventListener('click', function() {
                document.getElementById('snmp-port-detail-modal').classList.remove('active');
            });
        }

        // Modal Functions
        function openRackModal(rackToEdit = null) {
            const modal = document.getElementById('rack-modal');
            const form = document.getElementById('rack-form');
            const title = modal.querySelector('.modal-title');
            
            form.reset();
            
            if (rackToEdit) {
                title.textContent = 'Rack Düzenle';
                document.getElementById('rack-id').value = rackToEdit.id;
                document.getElementById('rack-name').value = rackToEdit.name;
                document.getElementById('rack-location').value = rackToEdit.location || '';
                document.getElementById('rack-slots').value = rackToEdit.slots || 42;
                document.getElementById('rack-description').value = rackToEdit.description || '';
            } else {
                title.textContent = 'Yeni Rack Ekle';
                document.getElementById('rack-id').value = '';
            }
            
            modal.classList.add('active');
        }

        // Port modalında patch panel seçimi
        async function loadPatchPanelsForPortModal(rackId) {
            const panelSelect = document.getElementById('patch-panel-select');
            const portInput = document.getElementById('patch-port-number');
            const display = document.getElementById('patch-display');
            
            panelSelect.innerHTML = '<option value="">Panel Seçin</option>';
            panelSelect.disabled = true;
            portInput.disabled = true;
            display.textContent = '';
            
            if (!rackId) return;
            
            try {
                const response = await fetch(`api/getPatchPanels.php?rack_id=${rackId}`);
                const result = await response.json();
                
                if (result.success && result.panels.length > 0) {
                    result.panels.forEach(panel => {
                        const option = document.createElement('option');
                        option.value = panel.id;
                        option.textContent = `Panel ${panel.panel_letter} (${panel.total_ports} port)`;
                        option.dataset.letter = panel.panel_letter;
                        panelSelect.appendChild(option);
                    });
                    
                    panelSelect.disabled = false;
                }
            } catch (error) {
                console.error('Paneller yüklenemedi:', error);
            }
        }

        function openBackupModal() {
            const modal = document.getElementById('backup-modal');
            const content = document.getElementById('backup-content');
            const activeTab = modal.querySelector('.tab-btn.active')?.dataset.backupTab || 'backup';
            
            if (activeTab === 'backup') {
                content.innerHTML = `
                    <div style="margin-bottom: 20px;">
                        <label class="form-label">Yedek Adı (Opsiyonel)</label>
                        <input type="text" id="backup-name" class="form-control" placeholder="Ör: Günlük Yedek">
                    </div>
                    <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 20px; margin-bottom: 20px;">
                        <h4 style="color: var(--primary); margin-bottom: 15px;">Yedekleme Detayları</h4>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                            <div>Switch Sayısı:</div>
                            <div style="text-align: right;">${switches.length}</div>
                            <div>Rack Sayısı:</div>
                            <div style="text-align: right;">${racks.length}</div>
                            <div>Patch Panel:</div>
                            <div style="text-align: right;">${patchPanels.length}</div>
                            <div>Fiber Panel:</div>
                            <div style="text-align: right;">${fiberPanels.length}</div>
                            <div>Aktif Port:</div>
                            <div style="text-align: right;">${Object.values(portConnections).reduce((acc, conns) => acc + conns.filter(c => c.device && c.device.trim() !== '' && c.type !== 'BOŞ').length, 0)}</div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button class="btn btn-primary" style="flex: 1;" id="create-backup-btn">
                            <i class="fas fa-save"></i> Yedek Oluştur
                        </button>
                    </div>
                `;
                
                document.getElementById('create-backup-btn').addEventListener('click', async () => {
                    const name = document.getElementById('backup-name').value || 'Yedek_' + new Date().toISOString().split('T')[0];
                    try {
                        const response = await fetch(`api/backup.php?action=create&name=${encodeURIComponent(name)}`);
                        const result = await response.json();
                        if (result.status === 'ok') {
                            showToast('Yedek oluşturuldu: ' + result.filename, 'success');
                            modal.classList.remove('active');
                        } else {
                            throw new Error(result.message);
                        }
                    } catch (error) {
                        showToast('Yedek oluşturulamadı: ' + error.message, 'error');
                    }
                });
            } else if (activeTab === 'restore') {
                content.innerHTML = `
                    <div style="text-align: center; padding: 20px; color: var(--text-light);">
                        <h4 style="color: var(--primary); margin-bottom: 15px;">Yedekleri Geri Yükle</h4>
                        <p>Yedekler klasöründeki yedekleri listelemek için "Yedekleri Listele" butonuna tıklayın.</p>
                        <button class="btn btn-primary" style="margin-top: 15px;" id="list-backups-btn">
                            <i class="fas fa-list"></i> Yedekleri Listele
                        </button>
                        <div id="backup-list" style="margin-top: 20px;"></div>
                    </div>
                `;
                
                document.getElementById('list-backups-btn').addEventListener('click', async () => {
                    try {
                        const response = await fetch('api/backup.php?action=list');
                        const result = await response.json();
                        if (result.status === 'ok') {
                            const backupList = document.getElementById('backup-list');
                            if (result.backups.length === 0) {
                                backupList.innerHTML = '<p>Henüz yedek bulunmamaktadır.</p>';
                                return;
                            }
                            
                            let html = '<div style="max-height: 300px; overflow-y: auto;">';
                            result.backups.forEach(backup => {
                                html += `
                                    <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px; margin-bottom: 10px;">
                                        <div style="display: flex; justify-content: space-between; align-items: center;">
                                            <div>
                                                <div style="font-weight: bold;">${backup.name}</div>
                                                <div style="font-size: 0.85rem; color: var(--text-light);">
                                                    ${backup.timestamp} (${Math.round(backup.size/1024)} KB)
                                                </div>
                                            </div>
                                            <button class="btn btn-success restore-btn" data-file="${backup.file}">
                                                <i class="fas fa-undo"></i> Geri Yükle
                                            </button>
                                        </div>
                                    </div>
                                `;
                            });
                            html += '</div>';
                            backupList.innerHTML = html;
                            
                            // Add event listeners to restore buttons
                            backupList.querySelectorAll('.restore-btn').forEach(btn => {
                                btn.addEventListener('click', async function() {
                                    const file = this.dataset.file;
                                    if (confirm(`"${file}" yedeğini geri yüklemek istediğinize emin misiniz? Mevcut verilerin üzerine yazılacaktır.`)) {
                                        try {
                                            const response = await fetch(`api/backup.php?action=restore&file=${encodeURIComponent(file)}`);
                                            const result = await response.json();
                                            if (result.status === 'ok') {
                                                showToast('Yedek başarıyla geri yüklendi', 'success');
                                                modal.classList.remove('active');
                                                await loadData();
                                            } else {
                                                throw new Error(result.message);
                                            }
                                        } catch (error) {
                                            showToast('Geri yükleme hatası: ' + error.message, 'error');
                                        }
                                    }
                                });
                            });
                        } else {
                            throw new Error(result.message);
                        }
                    } catch (error) {
                        showToast('Yedekler listelenemedi: ' + error.message, 'error');
                    }
                });
            } else if (activeTab === 'history') {
                content.innerHTML = `
                    <div style="text-align: center; padding: 40px; color: var(--text-light);">
                        <i class="fas fa-history" style="font-size: 3rem; margin-bottom: 20px;"></i>
                        <h4>Yedek Geçmişi</h4>
                        <p>Yedek geçmişini görmek için "Yedekleri Listele" butonuna tıklayın.</p>
                        <button class="btn btn-primary" style="margin-top: 15px;" id="list-backup-history-btn">
                            <i class="fas fa-list"></i> Yedekleri Listele
                        </button>
                        <div id="backup-history-list" style="margin-top: 20px;"></div>
                    </div>
                `;
                
                document.getElementById('list-backup-history-btn').addEventListener('click', async () => {
                    try {
                        const response = await fetch('api/backup.php?action=list');
                        const result = await response.json();
                        if (result.status === 'ok') {
                            const historyList = document.getElementById('backup-history-list');
                            if (result.backups.length === 0) {
                                historyList.innerHTML = '<p>Henüz yedek bulunmamaktadır.</p>';
                                return;
                            }
                            
                            let html = '<div style="max-height: 300px; overflow-y: auto;">';
                            result.backups.forEach(backup => {
                                const time = new Date(backup.timestamp);
                                const timeStr = time.toLocaleString('tr-TR');
                                html += `
                                    <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px; margin-bottom: 10px;">
                                        <div style="font-weight: bold; color: var(--primary);">${backup.name}</div>
                                        <div style="font-size: 0.85rem; color: var(--text-light); margin-top: 5px;">
                                            <i class="fas fa-calendar-alt"></i> ${timeStr}
                                        </div>
                                        <div style="font-size: 0.85rem; color: var(--text-light);">
                                            <i class="fas fa-database"></i> ${Math.round(backup.size/1024)} KB
                                        </div>
                                    </div>
                                `;
                            });
                            html += '</div>';
                            historyList.innerHTML = html;
                        } else {
                            throw new Error(result.message);
                        }
                    } catch (error) {
                        showToast('Geçmiş yüklenemedi: ' + error.message, 'error');
                    }
                });
            }
            
            modal.classList.add('active');
        }


        function exportExcel() {
            const workbook = XLSX.utils.book_new();
            
            switches.forEach(sw => {
                const sheetData = [
                    [sw.name],
                    ['Port', 'Description', 'IP', 'MAC', 'Connection/Device']
                ];
                
                const connections = portConnections[sw.id] || [];
                
                for (let i = 1; i <= sw.ports; i++) {
                    const connection = connections.find(c => c.port === i);
                    
                    if (connection && connection.device && connection.device.trim() !== '' && connection.type !== 'BOŞ') {
                        sheetData.push([
                            `Gi-${i}`,
                            connection.type,
                            connection.ip,
                            connection.mac,
                            connection.device
                        ]);
                    } else {
                        sheetData.push([`Gi-${i}`, '', '', '', '']);
                    }
                }
                
                const worksheet = XLSX.utils.aoa_to_sheet(sheetData);
                XLSX.utils.book_append_sheet(workbook, worksheet, sw.name.substring(0, 31));
            });
            
            const fileName = `Switch_Yonetimi_${new Date().toISOString().split('T')[0]}.xlsx`;
            XLSX.writeFile(workbook, fileName);
            showToast(`Excel dosyası başarıyla oluşturuldu: ${fileName}`, 'success');
        }

        // Search Function
        function search(query) {
            query = query.toLowerCase().trim();
            if (!query) return;
            
            const results = [];
            
            switches.forEach(sw => {
                // Switch adı, IP, marka, model ara
                if (sw.name.toLowerCase().includes(query) ||
                    sw.brand.toLowerCase().includes(query) ||
                    (sw.model && sw.model.toLowerCase().includes(query)) ||
                    (sw.ip && sw.ip.includes(query))) {
                    results.push({
                        type: 'switch',
                        data: sw
                    });
                }
            });
            
            // SNMP cihazlarını ara
            snmpDevices.forEach(device => {
                if (device.name && device.name.toLowerCase().includes(query) ||
                    device.ip_address && device.ip_address.includes(query) ||
                    device.vendor && device.vendor.toLowerCase().includes(query) ||
                    device.model && device.model.toLowerCase().includes(query)) {
                    results.push({
                        type: 'snmp_device',
                        data: device
                    });
                }
            });
            
            // Port bağlantılarında ara
            // Only treat query as a possible MAC/hex string when it consists
            // entirely of hex digits and common MAC separators: colon (:), hyphen (-),
            // and dot (.) — dot is included to support Cisco notation such as
            // "047c.16f5.5e7c".  Spaces are NOT included to avoid treating
            // innocent two-word queries as hex strings.
            // This prevents hostnames like "hakan" from stripping non-hex letters
            // (h,k,n → removed → "aa") and then false-matching every MAC address.
            const looksLikeMac = /^[0-9a-fA-F:\-.]+$/.test(query);
            const cleanQueryMac = looksLikeMac
                ? query.replace(/[^a-fA-F0-9]/g, '').toLowerCase()
                : '';

            switches.forEach(sw => {
                const connections = portConnections[sw.id] || [];
                connections.forEach(conn => {
                    // Uplink portları ara dışında tut: snmp_uplink_ports tablosunda kayıtlı
                    // portlar (örn. OTEL-ANTEN-UPLINK, gi50) arama sonuçlarına dahil edilmez.
                    // Also skip ports whose device name explicitly contains "UPLINK" (safety net
                    // for ports not yet registered in snmp_uplink_ports).
                    if (conn.is_uplink) return;
                    const devUpper = (conn.device || '').toUpperCase();
                    if (devUpper.includes('UPLINK')) return;

                    // Port bilgilerini ara
                    let found = false;
                    let matchedDevice = ''; // best matching device name from connection_info

                    // MAC adresi ara — only when query looks like a MAC/hex string
                    if (looksLikeMac && cleanQueryMac.length >= 4 && conn.mac) {
                        const cleanMac = conn.mac.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
                        if (cleanMac.includes(cleanQueryMac)) {
                            found = true;
                        }
                    }
                    
                    // IP adresi ara
                    if (conn.ip && conn.ip.includes(query)) {
                        found = true;
                    }
                    
                    // Cihaz adı ara (port'un kendi device etiketi)
                    if (conn.device && conn.device.toLowerCase().includes(query)) {
                        found = true;
                        if (!matchedDevice) matchedDevice = conn.device;
                    }

                    // SNMP port alias ara (switch üzerinde admin tanımladığı port açıklaması)
                    if (conn.snmp_port_alias && conn.snmp_port_alias.toLowerCase().includes(query)) {
                        found = true;
                        if (!matchedDevice) matchedDevice = conn.snmp_port_alias;
                    }
                    
                    // CONNECTION BİLGİLERİNDE ARA (hub/çoklu cihaz portları)
                    // Use the already-parsed conn.connections array when available,
                    // falling back to parsing conn.connection_info.
                    const connDataArr = (conn.connections && conn.connections.length > 0)
                        ? conn.connections
                        : (() => {
                            if (!conn.connection_info || conn.connection_info === '[]' || conn.connection_info === 'null') return [];
                            try { return JSON.parse(conn.connection_info); } catch(e) { return []; }
                        })();

                    connDataArr.forEach(connItem => {
                        if (connItem.device && connItem.device.toLowerCase().includes(query)) {
                            found = true;
                            // Prefer the first matching real device name (not generic placeholder)
                            if (!matchedDevice || /^Cihaz\s*\d*$/i.test(matchedDevice)) {
                                matchedDevice = connItem.device;
                            }
                        }
                        if (connItem.ip && connItem.ip.includes(query)) {
                            found = true;
                        }
                        // MAC in connection_info — same looksLikeMac guard
                        if (looksLikeMac && cleanQueryMac.length >= 4 && connItem.mac) {
                            const cleanConnMac = connItem.mac.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
                            if (cleanConnMac.includes(cleanQueryMac)) {
                                found = true;
                            }
                        }
                    });

                    // CONNECTION_INFO_PRESERVED BİLGİSİNDE ARA (fiber paneller vs için)
                    // Parse as JSON when possible and only check device/ip fields to
                    // avoid false positives from raw JSON boilerplate matching hostnames.
                    if (!found && conn.connection_info_preserved
                            && conn.connection_info_preserved !== '[]'
                            && conn.connection_info_preserved !== 'null') {
                        try {
                            const preserved = JSON.parse(conn.connection_info_preserved);
                            (Array.isArray(preserved) ? preserved : [preserved]).forEach(item => {
                                if (item.device && item.device.toLowerCase().includes(query)) found = true;
                                if (item.ip && item.ip.includes(query)) found = true;
                            });
                        } catch(e) {
                            // Not JSON — fall back to plain string search only for
                            // non-MAC queries to avoid hex false positives
                            if (!looksLikeMac && conn.connection_info_preserved.toLowerCase().includes(query)) {
                                found = true;
                            }
                        }
                    }
                    
                    if (found) {
                        results.push({
                            type: 'connection',
                            switch: sw,
                            connection: conn,
                            matchedDevice: matchedDevice  // real hostname matched, shown in result title
                        });
                    }
                });
            });
            
            // Rack'leri ara
            racks.forEach(rack => {
                if (rack.name.toLowerCase().includes(query) ||
                    (rack.location && rack.location.toLowerCase().includes(query))) {
                    results.push({
                        type: 'rack',
                        data: rack
                    });
                }
            });
            
            if (results.length === 0) {
                showToast('Arama sonucu bulunamadı', 'warning');
                return;
            }
            
            const modal = document.createElement('div');
            modal.className = 'modal-overlay active';
            modal.innerHTML = `
                <div class="modal" style="max-width: 600px;">
                    <div class="modal-header">
                        <h3 class="modal-title">Arama Sonuçları (${results.length})</h3>
                        <button class="modal-close" id="close-search-modal">&times;</button>
                    </div>
                    <div style="max-height: 400px; overflow-y: auto;">
                        ${results.map((result, index) => `
                            <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px; margin-bottom: 10px; cursor: pointer;"
                                 onclick="handleSearchResult(${JSON.stringify(result).replace(/"/g, '&quot;')})">
                                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                                    <div>
                                        <div style="font-weight: bold; color: var(--text); margin-bottom: 5px;">
                                            ${result.type === 'switch' ? 
                                                `<i class="fas fa-network-wired"></i> ${result.data.name}` :
                                                result.type === 'snmp_device' ?
                                                `<i class="fas fa-microchip"></i> ${result.data.name}` :
                                                result.type === 'connection' ? 
                                                `<i class="fas fa-plug"></i> Port ${result.connection.port} - ${result.matchedDevice || result.connection.device}` :
                                                `<i class="fas fa-server"></i> ${result.data.name}`}
                                        </div>
                                        <div style="font-size: 0.85rem; color: var(--text-light);">
                                            ${result.type === 'switch' ? 
                                                `${result.data.brand} • ${result.data.ports} Port` :
                                                result.type === 'snmp_device' ?
                                                `${result.data.vendor} ${result.data.model}` :
                                                result.type === 'connection' ? 
                                                `${result.connection.type} • ${result.switch.name}` :
                                                `${result.data.location} • ${result.data.slots || 42} Slot`}
                                        </div>
                                    </div>
                                    <span style="background: ${result.type === 'switch' ? 'var(--primary)' : result.type === 'snmp_device' ? '#8b5cf6' : result.type === 'connection' ? 'var(--success)' : 'var(--warning)'}; 
                                          color: white; padding: 3px 10px; border-radius: 12px; font-size: 0.8rem;">
                                        ${result.type === 'switch' ? 'SWITCH' : result.type === 'snmp_device' ? 'SNMP CİHAZ' : result.type === 'connection' ? 'BAĞLANTI' : 'RACK'}
                                    </span>
                                </div>
                                ${result.type === 'connection' ? `
                                    <div style="display: flex; gap: 15px; font-size: 0.85rem; color: var(--text-light); flex-wrap: wrap;">
                                        ${result.connection.ip ? `<span><i class="fas fa-network-wired"></i> ${result.connection.ip}</span>` : ''}
                                        ${result.connection.mac ? `<span><i class="fas fa-id-card"></i> ${result.connection.mac.length > 50 ? result.connection.mac.substring(0,50)+'…' : result.connection.mac}</span>` : ''}
                                        ${result.matchedDevice && result.matchedDevice !== result.connection.device ? `<span style="color: var(--success);"><i class="fas fa-user"></i> ${result.matchedDevice}</span>` : ''}
                                    </div>
                                ` : ''}
                                ${result.type === 'snmp_device' ? `
                                    <div style="display: flex; gap: 15px; font-size: 0.85rem; color: var(--text-light); flex-wrap: wrap;">
                                        <span><i class="fas fa-network-wired"></i> ***</span>
                                        <span><i class="fas fa-plug"></i> ${result.data.total_ports || 0} Port</span>
                                        <span><i class="fas fa-circle" style="color: ${result.data.status === 'online' ? 'var(--success)' : 'var(--danger)'};"></i> ${result.data.status}</span>
                                    </div>
                                ` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
            
            modal.querySelector('#close-search-modal').addEventListener('click', () => {
                modal.remove();
            });
            
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.remove();
                }
            });
        }

        // Initialize
        async function init() {
            console.log('Uygulama başlatılıyor...');
            
            await loadData();
            
            // Sidebar toggle
            sidebarToggle.addEventListener('click', () => {
                sidebar.classList.toggle('active');
            });
            
            homeButton.addEventListener('click', () => {
                switchPage('dashboard');
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
            
	
			
            document.querySelectorAll('.nav-item[data-page]').forEach(item => {
                item.addEventListener('click', function(e) {
                    e.preventDefault();
                    switchPage(this.dataset.page);
                    if (window.innerWidth <= 1024) {
                        sidebar.classList.remove('active');
                    }
                });
            });
            
            // Admin-only navigation event handlers
            <?php if ($currentUser['role'] === 'admin'): ?>
            const navAddSwitch = document.getElementById('nav-add-switch');
            if (navAddSwitch) {
                navAddSwitch.addEventListener('click', (e) => {
                    e.preventDefault();
                    openSwitchModal();
                });
            }
            
            const navAddRack = document.getElementById('nav-add-rack');
            if (navAddRack) {
                navAddRack.addEventListener('click', (e) => {
                    e.preventDefault();
                    openRackModal();
                });
            }
            
            const navAddPanel = document.getElementById('nav-add-panel');
            if (navAddPanel) {
                navAddPanel.addEventListener('click', (e) => {
                    e.preventDefault();
                    openPatchPanelModal();
                });
            }
            
            const navBackup = document.getElementById('nav-backup');
            if (navBackup) {
                navBackup.addEventListener('click', (e) => {
                    e.preventDefault();
                    openBackupModal();
                });
            }
            
            const navExport = document.getElementById('nav-export');
            if (navExport) {
                navExport.addEventListener('click', (e) => {
                    e.preventDefault();
                    exportExcel();
                });
            }
            <?php endif; ?>
            
            <?php if ($currentUser['role'] === 'admin'): ?>
            const navHistory = document.getElementById('nav-history');
            if (navHistory) {
                navHistory.addEventListener('click', (e) => {
                    e.preventDefault();
                    openBackupModal();
                    setTimeout(() => {
                        const historyTab = document.querySelector('[data-backup-tab="history"]');
                        if (historyTab) historyTab.click();
                    }, 100);
                });
            }
            <?php endif; ?>
            
            // ============================================
            // SLOT YÖNETİMİ EVENT LISTENER'LARI
            // ============================================

            // Switch Rack değiştiğinde slot listesini güncelle
            const switchRackSelect = document.getElementById('switch-rack');
            if (switchRackSelect) {
                switchRackSelect.addEventListener('change', function() {
                    console.log('Switch rack değişti:', this.value);
                    const rackId = this.value;
                    const positionSelect = document.getElementById('switch-position');
                    
                    if (!positionSelect) {
                        console.error('switch-position elementi bulunamadı!');
                        return;
                    }
                    
                    if (rackId) {
                        const switchId = document.getElementById('switch-id').value;
                        const currentSwitch = switchId ? switches.find(s => s.id == switchId) : null;
                        const currentPosition = currentSwitch ? currentSwitch.position_in_rack : null;
                        
                        console.log('Slot listesi güncelleniyor, mevcut pozisyon:', currentPosition);
                        updateAvailableSlots(rackId, 'switch', currentPosition);
                    } else {
                        positionSelect.innerHTML = '<option value="">Önce Rack Seçin</option>';
                        positionSelect.disabled = true;
                    }
                });
            } else {
                console.warn('switch-rack elementi bulunamadı');
            }

            // Patch Panel Rack değiştiğinde slot listesini güncelle
            const panelRackSelect = document.getElementById('panel-rack-select');
            if (panelRackSelect) {
                panelRackSelect.addEventListener('change', function() {
                    console.log('Panel rack değişti:', this.value);
                    const rackId = this.value;
                    const positionSelect = document.getElementById('panel-position');
                    
                    if (!positionSelect) {
                        console.error('panel-position elementi bulunamadı!');
                        return;
                    }
                    
                    if (rackId) {
                        updateAvailableSlots(rackId, 'panel');
                    } else {
                        positionSelect.innerHTML = '<option value="">Önce Rack Seçin</option>';
                        positionSelect.disabled = true;
                    }
                });
            } else {
                console.warn('panel-rack-select elementi bulunamadı');
            }
            
            // Fiber Panel Rack değiştiğinde slot listesini güncelle
            const fiberPanelRackSelect = document.getElementById('fiber-panel-rack-select');
            if (fiberPanelRackSelect) {
                fiberPanelRackSelect.addEventListener('change', function() {
                    console.log('Fiber Panel rack değişti:', this.value);
                    const rackId = this.value;
                    const positionSelect = document.getElementById('fiber-panel-position');
                    
                    if (!positionSelect) {
                        console.error('fiber-panel-position elementi bulunamadı!');
                        return;
                    }
                    
                    if (rackId) {
                        updateAvailableSlotsForFiber(rackId);
                    } else {
                        positionSelect.innerHTML = '<option value="">Önce Rack Seçin</option>';
                        positionSelect.disabled = true;
                    }
                });
            } else {
                console.warn('fiber-panel-rack-select elementi bulunamadı');
            }
            
            // ============================================
            // HUB PORT EVENT LISTENER'LARI
            // ============================================

            // Hub Modal Event Listeners
            document.getElementById('close-hub-modal').addEventListener('click', closeHubModal);
            document.getElementById('close-hub-edit-modal').addEventListener('click', closeHubEditModal);
            document.getElementById('cancel-hub-btn').addEventListener('click', closeHubEditModal);

            // Hub Device Ekleme
            document.getElementById('add-hub-device').addEventListener('click', function() {
                const devicesList = document.getElementById('hub-devices-list');
                const scrollContainer = devicesList.querySelector('div');
                const currentRows = scrollContainer.querySelectorAll('.hub-device-row');
                const newIndex = currentRows.length;
                
                addDeviceRowToContainer(scrollContainer, newIndex);
            });

            // Çoklu cihaz ekleme butonu
            document.getElementById('add-multiple-devices').addEventListener('click', function() {
                const count = parseInt(prompt('Kaç adet cihaz eklemek istiyorsunuz? (1-50)', '5'));
                
                if (isNaN(count) || count < 1 || count > 50) {
                    showToast('Lütfen 1-50 arasında bir sayı girin', 'warning');
                    return;
                }
                
                const devicesList = document.getElementById('hub-devices-list');
                const scrollContainer = devicesList.querySelector('div');
                const currentRows = scrollContainer.querySelectorAll('.hub-device-row');
                const startIndex = currentRows.length;
                
                for (let i = 0; i < count; i++) {
                    const index = startIndex + i;
                    addDeviceRowToContainer(scrollContainer, index);
                }
                
                showToast(`${count} yeni cihaz satırı eklendi`, 'success');
            });

            // Hub Form Submit
            document.getElementById('hub-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const switchId = document.getElementById('hub-switch-id').value;
                const portNo = document.getElementById('hub-port-number').value;
                const hubName = document.getElementById('hub-name').value;
                const hubType = document.getElementById('hub-type').value;
                
                if (!hubName.trim()) {
                    showToast('Hub adı girmelisiniz', 'warning');
                    return;
                }
                
                // Cihaz verilerini topla
                const devices = [];
                const deviceRows = document.querySelectorAll('.hub-device-row');
                
                deviceRows.forEach(row => {
                    const deviceInput = row.querySelector('.hub-device-name');
                    const ipInput = row.querySelector('.hub-device-ip');
                    const macInput = row.querySelector('.hub-device-mac');
                    const typeSelect = row.querySelector('.hub-device-type');
                    
                    // Sadece dolu satırları ekle
                    if (deviceInput.value.trim() || ipInput.value.trim() || macInput.value.trim()) {
                        devices.push({
                            device: deviceInput.value.trim(),
                            ip: ipInput.value.trim(),
                            mac: macInput.value.trim(),
                            type: typeSelect.value
                        });
                    }
                });
                
                // Eğer hiç cihaz yoksa, en az bir boş satır ekle
                if (devices.length === 0) {
                    devices.push({
                        device: '',
                        ip: '',
                        mac: '',
                        type: 'DEVICE'
                    });
                }
                
                const formData = {
                    switchId: switchId,
                    port: portNo,
                    isHub: 1,
                    hubName: hubName,
                    connections: JSON.stringify(devices), // JSON string olarak gönder
                    type: 'HUB' // Tipi HUB olarak ayarla
                };
                
                try {
                    const response = await fetch('actions/updatePort.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(formData)
                    });
                    
                    const result = await response.json();
                    if (result.status === 'ok') {
                        showToast('Hub portu güncellendi', 'success');
                        closeHubEditModal();
                        await loadData();
                        
                        // Switch detail'i yenile
                        if (selectedSwitch && selectedSwitch.id == switchId) {
                            const sw = switches.find(s => s.id == switchId);
                            if (sw) showSwitchDetail(sw);
                        }
                    } else {
                        throw new Error(result.message);
                    }
                } catch (error) {
                    console.error('Hub güncelleme hatası:', error);
                    showToast('Hub güncellenemedi: ' + error.message, 'error');
                }
            });

            // Hub'ı kaldır
            document.getElementById('remove-hub-btn').addEventListener('click', async function() {
                const switchId = document.getElementById('hub-switch-id').value;
                const portNo = document.getElementById('hub-port-number').value;
                
                if (confirm('Bu hub bağlantısını kaldırmak istediğinize emin misiniz?')) {
                    const formData = {
                        switchId: switchId,
                        port: portNo,
                        type: 'ETHERNET',
                        device: '',
                        ip: '',
                        mac: '',
                        isHub: 0,
                        hubName: '',
                        connections: ''
                    };
                    
                    try {
                        await savePort(formData);
                        closeHubEditModal();
                    } catch (error) {
                        console.error('Hub kaldırma hatası:', error);
                    }
                }
            });

            // Hub Devices List'te remove butonları için event delegation
            document.getElementById('hub-devices-list').addEventListener('click', function(e) {
                if (e.target.closest('.remove-device')) {
                    const row = e.target.closest('.hub-device-row');
                    if (row) {
                        row.remove();
                        
                        // Kalan satırların numaralarını yeniden düzenle
                        const scrollContainer = this.querySelector('div');
                        const remainingRows = scrollContainer.querySelectorAll('.hub-device-row');
                        
                        remainingRows.forEach((row, index) => {
                            const numberDiv = row.querySelector('div:first-child');
                            if (numberDiv) {
                                numberDiv.textContent = index + 1;
                            }
                        });
                        
                        // Eğer hiç satır kalmadıysa bir tane ekle
                        if (remainingRows.length === 0) {
                            addDeviceRowToContainer(scrollContainer, 0);
                        }
                    }
                }
            });

            // ============================================
            // FIBER PANEL EVENT LISTENER'LARI
            // ============================================

            // Fiber Panel form submit
            document.getElementById('fiber-panel-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                console.log('Fiber panel form submit edildi');
                
                const rackSelect = document.getElementById('fiber-panel-rack-select');
                const panelLetterSelect = document.getElementById('fiber-panel-letter');
                const fiberCountSelect = document.getElementById('fiber-count');
                const positionSelect = document.getElementById('fiber-panel-position');
                const descriptionInput = document.getElementById('fiber-panel-description');
                
                const formData = {
                    rackId: rackSelect.value,
                    panelLetter: panelLetterSelect.value,
                    totalFibers: fiberCountSelect.value,
                    positionInRack: positionSelect.value,
                    description: descriptionInput.value
                };
                
                console.log('Fiber panel form data:', formData);
                
                // Validasyon
                if (!formData.rackId || formData.rackId <= 0) {
                    showToast('Lütfen bir rack seçin', 'error');
                    return;
                }
                
                if (!formData.panelLetter) {
                    showToast('Lütfen panel harfi seçin', 'error');
                    return;
                }
                
                if (!formData.positionInRack || formData.positionInRack <= 0) {
                    showToast('Lütfen bir slot pozisyonu seçin', 'error');
                    return;
                }
                
                try {
                    await saveFiberPanel(formData);
                } catch (error) {
                    // Hata zaten gösterildi
                }
            });

            document.querySelectorAll('.modal-close, .modal-overlay').forEach(element => {
                if (element.classList.contains('modal-close')) {
                    element.addEventListener('click', function() {
                        this.closest('.modal-overlay').classList.remove('active');
                    });
                } else if (element.classList.contains('modal-overlay')) {
                    element.addEventListener('click', function(e) {
                        if (e.target === this) {
                            this.classList.remove('active');
                        }
                    });
                }
            });
            
            // Switch Form Submit
            document.getElementById('switch-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                console.log('Switch form submit edildi');
                
                // Position değerini al
                const positionSelect = document.getElementById('switch-position');
                let position = null;
                
                if (positionSelect && positionSelect.value) {
                    position = parseInt(positionSelect.value);
                    console.log('Seçilen slot:', position);
                } else {
                    console.log('Slot seçilmedi, otomatik yerleştirilecek');
                }
                
                // Form verilerini topla
                const portsEl = document.getElementById('switch-ports');
                const formData = {
                    id: document.getElementById('switch-id').value,
                    name: document.getElementById('switch-name').value,
                    brand: document.getElementById('switch-brand').value,
                    model: document.getElementById('switch-model').value,
                    ports: portsEl.disabled ? parseInt(portsEl.value) || 0 : parseInt(portsEl.value),
                    status: document.getElementById('switch-status').value,
                    rackId: parseInt(document.getElementById('switch-rack').value),
                    positionInRack: position,
                    ip: document.getElementById('switch-ip').value,
                    is_core: parseInt(document.getElementById('switch-is-core').value) || 0,
                    is_virtual: parseInt(document.getElementById('switch-is-virtual').value) || 0
                };
                
                console.log('Form data:', formData);
                
                // Validasyon
                if (!formData.rackId || formData.rackId <= 0) {
                    showToast('Lütfen bir rack seçin', 'error');
                    return;
                }
                
                // Update veya Add
                if (formData.id) {
                    await updateSwitch(formData);
                } else {
                    await addSwitch(formData);
                }
                
                // Modal'ı kapat
                document.getElementById('switch-modal').classList.remove('active');
            });
            
         // --- Rack form submit (GÜNCELLENDİ) ---
document.getElementById('rack-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const formData = {
        id: document.getElementById('rack-id').value,
        name: document.getElementById('rack-name').value,
        location: document.getElementById('rack-location').value,
        description: document.getElementById('rack-description').value,
        slots: parseInt(document.getElementById('rack-slots').value)
    };

    // Basic validation
    if (!formData.name || formData.name.trim() === '') {
        showToast('Rack adı boş olamaz', 'warning');
        return;
    }
    if (!formData.slots || formData.slots < 1 || formData.slots > 100) {
        showToast('Slot sayısı 1-100 arası olmalıdır', 'warning');
        return;
    }

    // Eğer düzenleme ise (id varsa) -> ön kontrol: mevcut rack içindeki switch/panel pozisyonlarını kontrol et
    if (formData.id) {
        const rackId = parseInt(formData.id);
        // Bulunduğumuz client-side veri setinden kontrol et
        const rackSwitches = switches.filter(s => s.rack_id == rackId && s.position_in_rack);
        const rackPatchPanels = patchPanels.filter(p => p.rack_id == rackId && p.position_in_rack);
        const rackFiberPanels = fiberPanels.filter(fp => fp.rack_id == rackId && fp.position_in_rack);

        // En yüksek kullanılan slot numarasını al
        let maxUsedSlot = 0;
        rackSwitches.forEach(s => { if (s.position_in_rack && s.position_in_rack > maxUsedSlot) maxUsedSlot = s.position_in_rack; });
        rackPatchPanels.forEach(p => { if (p.position_in_rack && p.position_in_rack > maxUsedSlot) maxUsedSlot = p.position_in_rack; });
        rackFiberPanels.forEach(fp => { if (fp.position_in_rack && fp.position_in_rack > maxUsedSlot) maxUsedSlot = fp.position_in_rack; });

        if (formData.slots < maxUsedSlot) {
            // Kullanıcıya net bilgi ver ve iptal et
            showToast(`Bu rack için seçtiğiniz slot sayısı (${formData.slots}) mevcut en yüksek kullanılan slot (${maxUsedSlot}) değerinden küçük. Lütfen önce cihaz/panel pozisyonlarını taşıyın veya slot sayısını daha büyük seçin.`, 'error', 8000);
            return;
        }
    }

    // Gönder
    try {
        showLoading();
        const response = await fetch('actions/saveRack.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(formData)
        });
        const result = await response.json();
        if (result.success) {
            showToast('Rack başarıyla kaydedildi', 'success');
            document.getElementById('rack-modal').classList.remove('active');
            await loadData();
            loadRacksPage();
        } else {
            throw new Error(result.error || result.message || 'Rack kaydedilemedi');
        }
    } catch (error) {
        console.error('Rack güncelleme hatası:', error);
        showToast('Rack güncelleme hatası: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
});
            
            // Patch Panel form submit
            document.getElementById('patch-panel-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                console.log('Patch Panel form submit edildi');
                
                // Position değerini al
                const positionSelect = document.getElementById('panel-position');
                let position = null;
                
                if (positionSelect && positionSelect.value) {
                    position = parseInt(positionSelect.value);
                    console.log('Seçilen panel slotu:', position);
                } else {
                    showToast('Lütfen bir slot seçin', 'error');
                    return;
                }
                
                // Form verilerini topla
                const formData = {
                    rackId: document.getElementById('panel-rack-select').value,
                    panelLetter: document.getElementById('panel-letter').value,
                    totalPorts: document.getElementById('panel-port-count').value,
                    positionInRack: position,
                    description: document.getElementById('panel-description').value
                };
                
                console.log('Patch Panel form data:', formData);
                
                // Validasyon
                if (!formData.rackId || formData.rackId <= 0) {
                    showToast('Lütfen bir rack seçin', 'error');
                    return;
                }
                
                if (!formData.panelLetter) {
                    showToast('Lütfen panel harfi seçin', 'error');
                    return;
                }
                
                // API çağrısı
                try {
                    const response = await fetch('actions/savePatchPanel.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(formData)
                    });
                    
                    const result = await response.json();
                    if (result.success) {
                        showToast('Patch panel başarıyla eklendi', 'success');
                        document.getElementById('patch-panel-modal').classList.remove('active');
                        
                        // Verileri yenile
                        await loadData();
                        loadRacksPage();
                        updateStats();
                    } else {
                        throw new Error(result.error);
                    }
                } catch (error) {
                    console.error('Patch panel ekleme hatası:', error);
                    showToast('Patch panel eklenemedi: ' + error.message, 'error');
                }
            });
            
            document.getElementById('port-clear-btn').addEventListener('click', async function() {
                const switchId = document.getElementById('port-switch-id').value;
                const portNumber = document.getElementById('port-number').value;
                
                if (confirm(`Port ${portNumber} bağlantısını boşa çekmek istediğinize emin misiniz?`)) {
                    const formData = {
                        switchId: switchId,
                        port: portNumber,
                        type: 'BOŞ',
                        device: '',
                        ip: '',
                        mac: '',
                        connectionInfo: '',
                        panelId: null,
                        panelPort: null,
                        panelType: null
                    };
                    
                    try {
                        showLoading();
                        
                        const response = await fetch('actions/savePortWithPanel.php', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(formData)
                        });
                        
                        const result = await response.json();
                        
                        if (result.success) {
                            showToast('Port bağlantısı boşa çekildi', 'success');
                            document.getElementById('port-modal').classList.remove('active');
                            await loadData();
                            
                            // Switch detail'i yenile
                            if (selectedSwitch && selectedSwitch.id == switchId) {
                                const sw = switches.find(s => s.id == switchId);
                                if (sw) showSwitchDetail(sw);
                            }
                        } else {
                            throw new Error(result.error || 'İşlem başarısız');
                        }
                    } catch (error) {
                        console.error('Port temizleme hatası:', error);
                        showToast('Port temizlenemedi: ' + error.message, 'error');
                    } finally {
                        hideLoading();
                    }
                }
            });
            
            
            // Rack detail modal event listener'ları
            document.getElementById('close-rack-detail-modal').addEventListener('click', () => {
                document.getElementById('rack-detail-modal').classList.remove('active');
            });
            
            document.getElementById('rack-detail-modal').addEventListener('click', function(e) {
                if (e.target === this) {
                    this.classList.remove('active');
                }
            });

            // ============================================
            // PANEL DETAIL MODAL EVENT LISTENER'LARI
            // ============================================

            // Rack Device (Hub SW / Server) detail modal event listeners
            document.getElementById('close-rd-device-modal').addEventListener('click', () => {
                document.getElementById('rd-device-modal').classList.remove('active');
            });

            document.getElementById('rd-device-modal').addEventListener('click', function(e) {
                if (e.target === this) {
                    this.classList.remove('active');
                }
            });

            // Panel detail modal event listener'ları
            document.getElementById('close-panel-detail-modal').addEventListener('click', () => {
                document.getElementById('panel-detail-modal').classList.remove('active');
            });

            document.getElementById('panel-detail-modal').addEventListener('click', function(e) {
                if (e.target === this) {
                    this.classList.remove('active');
                }
            });
            
            document.querySelectorAll('.tab-btn').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabContent = this.dataset.tab;
                    const container = this.closest('.tabs');
                    
                    container.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
                    this.classList.add('active');
                    
                    if (tabContent) {
                        loadSwitchesPage();
                    }
                });
            });
            
            document.querySelectorAll('[data-backup-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabId = this.dataset.backupTab;
                    const container = this.closest('.tabs');
                    
                    container.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
                    this.classList.add('active');
                    
                    openBackupModal();
                });
            });
            
            document.getElementById('dashboard-search').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    search(this.value);
                }
            });

            // All page search boxes call the same global search function
            document.querySelectorAll('.page-search').forEach(function(input) {
                input.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        search(this.value);
                    }
                });
            });
            
            showToast('Modern Rack & Switch Yönetim Sistemi başlatıldı', 'success');
            hideLoading();
            
            window.handleSearchResult = function(result) {
                if (result.type === 'switch') {
                    showSwitchDetail(result.data);
                } else if (result.type === 'connection') {
                    showSwitchDetail(result.switch);
                    setTimeout(() => {
                        const portElement = document.querySelector(`.port-item[data-port="${result.connection.port}"]`);
                        if (portElement) {
                            const originalBorder = portElement.style.borderColor;
                            portElement.style.borderColor = '#fbbf24';
                            portElement.style.boxShadow = '0 0 20px #fbbf24';
                            
                            setTimeout(() => {
                                portElement.style.borderColor = originalBorder;
                                portElement.style.boxShadow = '';
                            }, 3000);
                        }
                    }, 500);
                } else if (result.type === 'rack') {
                    showRackDetail(result.data);
                } else if (result.type === 'snmp_device') {
                    // SNMP cihazı için SNMP sekmesini göster
                    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
                    document.querySelectorAll('.page-content').forEach(page => page.style.display = 'none');
                    document.querySelector('[data-page="snmp"]').classList.add('active');
                    document.getElementById('page-snmp').style.display = 'block';
                    showToast(`SNMP Cihazı: ${result.data.name}`, 'info');
                }
                
                const modal = document.querySelector('.modal-overlay.active');
                if (modal) modal.remove();
            };
            
            // Port Alarms functionality
            let currentAlarmFilter = 'all';
            // Global map: key = "deviceId:portNumber" → true — used to highlight ports with active alarms
            window._portAlarmsMap = {};
            
            async function loadPortAlarms(filter = 'all') {
                try {
                    const response = await fetch('api/port_change_api.php?action=get_active_alarms');
                    const data = await response.json();
                    
                    if (!data.success) {
                        throw new Error(data.error || 'Failed to load alarms');
                    }
                    
                    displayAlarms(data.alarms, filter);
                    updateAlarmBadge(data.alarms.length);
                    // Update global alarm map so port grid can highlight alarmed ports
                    window._portAlarmsMap = {};
                    (data.alarms || []).forEach(a => {
                        if (a.device_id && a.port_number) {
                            window._portAlarmsMap[`${a.device_id}:${a.port_number}`] = true;
                        }
                    });
                } catch (error) {
                    console.error('Error loading alarms:', error);
                    document.getElementById('alarms-list-container').innerHTML = `
                        <div style="text-align: center; padding: 40px; color: var(--danger);">
                            <i class="fas fa-exclamation-circle" style="font-size: 32px; margin-bottom: 15px;"></i>
                            <p>Alarmlar yüklenirken hata oluştu</p>
                            <p style="font-size: 0.9rem; color: var(--text-light);">${error.message}</p>
                        </div>
                    `;
                }
            }
            // Expose loadPortAlarms globally so other script blocks can trigger a refresh
            window.loadPortAlarms = (filter) => loadPortAlarms(filter);
            
            function displayAlarms(alarms, filter) {
                const container = document.getElementById('alarms-list-container');
                
                if (!container) {
                    console.error('alarms-list-container not found');
                    return;
                }
                
                if (!alarms || alarms.length === 0) {
                    container.innerHTML = `
                        <div style="text-align: center; padding: 40px; color: var(--text-light);">
                            <i class="fas fa-check-circle" style="font-size: 48px; color: var(--success); margin-bottom: 15px;"></i>
                            <p style="font-size: 1.2rem;">Aktif alarm bulunmuyor</p>
                            <p style="font-size: 0.9rem;">Tüm portlar normal durumda</p>
                        </div>
                    `;
                    // Update severity counts display
                    updateSeverityCounts(alarms || []);
                    return;
                }
                
                // Filter alarms
                let filteredAlarms = alarms;
                if (filter !== 'all') {
                    filteredAlarms = alarms.filter(a => a.alarm_type === filter);
                }
                
                // Update severity counts display (always show total counts)
                updateSeverityCounts(alarms);
                
                if (filteredAlarms.length === 0) {
                    container.innerHTML = `
                        <div style="text-align: center; padding: 40px; color: var(--text-light);">
                            <i class="fas fa-filter" style="font-size: 32px; margin-bottom: 15px;"></i>
                            <p>Bu kategoride alarm bulunmuyor</p>
                        </div>
                    `;
                    return;
                }
                
                let html = '';
                filteredAlarms.forEach(alarm => {
                    const severityClass = alarm.severity.toLowerCase();
                    const isSilenced = alarm.is_silenced == 1;
                    const isAcknowledged = alarm.acknowledged_at != null;
                    
                    html += `
                        <div class="alarm-list-item ${severityClass} ${isSilenced ? 'silenced' : ''}" data-alarm-id="${alarm.id}">
                            <div class="alarm-header-row">
                                <div class="alarm-title-text" style="cursor: pointer;" onclick="navigateToAlarmPort(${alarm.device_id}, ${alarm.port_number || 0}, '${alarm.device_name}', '${alarm.device_ip || ''}')">
                                    <i class="fas fa-network-wired"></i> ${alarm.device_name}${alarm.port_number ? ' - Port ' + alarm.port_number : ''}
                                </div>
                                <span class="alarm-severity-badge ${severityClass}">${alarm.severity}</span>
                            </div>
                            <div class="alarm-message">${maskIPs(alarm.message)}</div>
                            ${(() => {
                                const isHubAlarm = (alarm.old_value || '').includes(',') || (alarm.new_value || '').includes(',');
                                if (isHubAlarm || !alarm.old_value || !alarm.new_value) return '';
                                return `<div style="margin: 8px 0; padding: 8px; background: rgba(0,0,0,0.2); border-radius: 5px; word-break: break-all; overflow-wrap: break-word;">
                                    <span style="color: var(--danger);">${alarm.old_value}</span>
                                    <i class="fas fa-arrow-right" style="margin: 0 8px;"></i>
                                    <span style="color: var(--success);">${alarm.new_value}</span>
                                </div>`;
                            })()}
                            <div class="alarm-meta">
                                <span><i class="fas fa-clock"></i> ${new Date(alarm.last_occurrence).toLocaleString('tr-TR')}</span>
                                ${alarm.occurrence_count > 1 ? `<span><i class="fas fa-redo"></i> ${alarm.occurrence_count}x</span>` : ''}
                            </div>
                            ${isSilenced ? `
                                <div style="padding: 8px; background: rgba(255, 193, 7, 0.2); border-radius: 5px; margin: 8px 0;">
                                    <i class="fas fa-volume-mute"></i> <strong>Sesize alındı</strong>
                                </div>
                            ` : ''}
                            ${isAcknowledged ? `
                                <div style="padding: 8px; background: rgba(40, 167, 69, 0.2); border-radius: 5px; margin: 8px 0;">
                                    <i class="fas fa-check"></i> <strong>Bilgi dahilinde</strong>
                                </div>
                            ` : ''}
                            <div class="alarm-actions" style="margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap;">
                                ${!isAcknowledged ? `
                                    ${(() => {
                                        const isHubAlarm = (alarm.old_value || '').includes(',') || (alarm.new_value || '').includes(',');
                                        const isMacAlarm = alarm.alarm_type === 'mac_moved' || alarm.alarm_type === 'mac_added';
                                        if (isHubAlarm && isMacAlarm) {
                                            return `<button class="btn btn-sm" style="background: #27ae60; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: bold;" onclick="event.stopPropagation(); closeHubAlarmIndex(${alarm.id})">
                                                <i class="fas fa-check-circle"></i> Alarm Kapat
                                            </button>`;
                                        } else if (isMacAlarm && alarm.new_value && isValidMacAddress(alarm.new_value)) {
                                            return `<button class="btn btn-sm" style="background: #27ae60; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: bold;" onclick="event.stopPropagation(); saveMacAndCloseAlarm(${alarm.id}, '${alarm.new_value}')">
                                                <i class="fas fa-save"></i> MAC Kaydet ve Kapat (${alarm.new_value.replace(/</g,'&lt;').replace(/>/g,'&gt;')})
                                            </button>`;
                                        } else if (alarm.alarm_type === 'mac_moved' && alarm.mac_address) {
                                            return `<button class="btn btn-sm" style="background: #8b5cf6; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: bold;" onclick="event.stopPropagation(); showIndexAlarmDetails(${alarm.id})">
                                                <i class="fas fa-arrows-alt-h"></i> Portu Taşı
                                            </button>`;
                                        } else if (alarm.alarm_type === 'hub_unknown_mac' && alarm.new_value) {
                                            return `<button class="btn btn-sm" style="background: #27ae60; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: bold;" onclick="event.stopPropagation(); window.open('pages/device_import.php?mac=${encodeURIComponent((alarm.new_value||'').replace(/[^0-9A-Fa-f:.\-]/g,''))}', '_blank')">
                                                <i class="fas fa-exchange-alt"></i> MAC İşle
                                            </button>`;
                                        }
                                        return '';
                                    })()}
                                    <button class="btn btn-sm" style="background: #3498db; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer;" onclick="event.stopPropagation(); acknowledgeIndexAlarm(${alarm.id})">
                                        <i class="fas fa-check"></i> Bilgi Dahilinde Kapat
                                    </button>
                                    <button class="btn btn-sm" style="background: #e67e22; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer;" onclick="event.stopPropagation(); silenceIndexAlarm(${alarm.id})">
                                        <i class="fas fa-volume-mute"></i> Alarmı Sesize Al
                                    </button>
                                ` : ''}
                                <button class="btn btn-sm" style="background: #95a5a6; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer;" onclick="event.stopPropagation(); showIndexAlarmDetails(${alarm.id})">
                                    <i class="fas fa-info-circle"></i> Detaylar
                                </button>
                            </div>
                        </div>
                    `;
                });
                
                container.innerHTML = html;
            }
            
            // Update severity counts display
            function updateSeverityCounts(alarms) {
                const counts = {
                    CRITICAL: 0,
                    HIGH: 0,
                    MEDIUM: 0,
                    LOW: 0,
                    INFO: 0
                };
                
                alarms.forEach(alarm => {
                    const severity = alarm.severity.toUpperCase();
                    if (counts.hasOwnProperty(severity)) {
                        counts[severity]++;
                    }
                });
                
                // Update the severity display in modal header if it exists
                const severityDisplay = document.getElementById('alarm-severity-counts');
                if (severityDisplay) {
                    severityDisplay.innerHTML = `
                        <div style="display: flex; gap: 15px; flex-wrap: wrap; margin-top: 10px;">
                            <span style="padding: 4px 10px; background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; border-radius: 5px; color: #ef4444; font-weight: bold;">
                                <i class="fas fa-exclamation-circle"></i> Critical: ${counts.CRITICAL}
                            </span>
                            <span style="padding: 4px 10px; background: rgba(245, 158, 11, 0.2); border: 1px solid #f59e0b; border-radius: 5px; color: #f59e0b; font-weight: bold;">
                                <i class="fas fa-exclamation-triangle"></i> High: ${counts.HIGH}
                            </span>
                            <span style="padding: 4px 10px; background: rgba(234, 179, 8, 0.2); border: 1px solid #eab308; border-radius: 5px; color: #eab308; font-weight: bold;">
                                <i class="fas fa-info-circle"></i> Medium: ${counts.MEDIUM}
                            </span>
                            <span style="padding: 4px 10px; background: rgba(148, 163, 184, 0.2); border: 1px solid #94a3b8; border-radius: 5px; color: #94a3b8; font-weight: bold;">
                                <i class="fas fa-check-circle"></i> Low: ${counts.LOW}
                            </span>
                        </div>
                    `;
                }
            }
            
            function updateAlarmBadge(count) {
                const badge = document.getElementById('alarm-badge');
                if (badge) {
                    if (count > 0) {
                        badge.textContent = count;
                        badge.style.display = 'inline-block';
                    } else {
                        badge.style.display = 'none';
                    }
                }
            }
            
            window.navigateToAlarmPort = async function(deviceId, portNumber, deviceName, deviceIp) {
                // Close alarm modal
                document.getElementById('port-alarms-modal').classList.remove('active');
                
                // Find the switch by name or IP (not by snmp_device ID)
                // Try name first, then IP
                let switchData = switches.find(s => s.name === deviceName);
                if (!switchData && deviceIp) {
                    switchData = switches.find(s => s.ip === deviceIp);
                }
                
                if (switchData) {
                    // Show switch detail
                    await showSwitchDetail(switchData);
                    
                    // Wait a bit for ports to render
                    setTimeout(() => {
                        const portElement = document.querySelector(`.port-item[data-port="${portNumber}"]`);
                        if (portElement) {
                            // Highlight port in RED
                            portElement.style.borderColor = '#ef4444';
                            portElement.style.borderWidth = '3px';
                            portElement.style.boxShadow = '0 0 25px #ef4444';
                            portElement.style.backgroundColor = '#fee2e2';
                            
                            // Scroll to port
                            portElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            
                            // Remove highlight after 5 seconds
                            setTimeout(() => {
                                portElement.style.borderColor = '';
                                portElement.style.borderWidth = '';
                                portElement.style.boxShadow = '';
                                portElement.style.backgroundColor = '';
                            }, 5000);
                            
                            showToast(`${deviceName} - Port ${portNumber} vurgulandı`, 'info');
                        } else {
                            showToast(`Port ${portNumber} bulunamadı`, 'warning');
                        }
                    }, 500);
                } else {
                    showToast(`Switch bulunamadı: ${deviceName}`, 'error');
                    console.warn('Switch not found. Searched for:', { deviceName, deviceIp, switches });
                }
            };
            
            // Port alarms modal handlers removed - now using page navigation
            
            document.getElementById('port-alarms-modal')?.addEventListener('click', function(e) {
                if (e.target === this) {
                    this.classList.remove('active');
                }
            });
            
            // Alarm action functions for index page - GLOBAL SCOPE
            window.closeHubAlarmIndex = async function(alarmId) {
                try {
                    const formData = new FormData();
                    formData.append('action', 'acknowledge_alarm');
                    formData.append('alarm_id', alarmId);
                    formData.append('ack_type', 'known_change');
                    formData.append('note', 'Hub MAC değişikliği kabul edildi');
                    const response = await fetch('api/port_change_api.php', { method: 'POST', body: formData });
                    const data = await response.json();
                    if (data.success) {
                        showNotification('Alarm kapatıldı', 'success');
                        loadPortAlarms(currentAlarmFilter);
                    } else {
                        showNotification(data.error || 'Hata oluştu', 'error');
                    }
                } catch (error) {
                    showNotification('İşlem başarısız oldu', 'error');
                }
            };

            window.saveMacAndCloseAlarm = async function(alarmId, newMac) {
                if (!confirm(`Yeni MAC adresi (${newMac}) porta kaydedilecek ve alarm kapatılacak. Onaylıyor musunuz?`)) {
                    return;
                }
                
                try {
                    const formData = new FormData();
                    formData.append('action', 'acknowledge_alarm');
                    formData.append('alarm_id', alarmId);
                    formData.append('ack_type', 'known_change');
                    formData.append('note', 'MAC kaydedildi: ' + newMac);
                    
                    const response = await fetch('api/port_change_api.php', {
                        method: 'POST',
                        body: formData
                    });
                    const data = await response.json();
                    
                    if (data.success) {
                        showNotification('MAC adresi kaydedildi ve alarm kapatıldı: ' + newMac, 'success');
                        loadPortAlarms(currentAlarmFilter);
                    } else {
                        showNotification(data.error || 'Hata oluştu', 'error');
                    }
                } catch (error) {
                    console.error('Error saving MAC and closing alarm:', error);
                    showNotification('İşlem başarısız oldu', 'error');
                }
            };
            
            window.acknowledgeIndexAlarm = async function(alarmId) {
                if (!confirm('Bu alarmı bilgi dahilinde kapatmak istediğinizden emin misiniz?')) {
                    return;
                }
                
                try {
                    const response = await fetch(`api/port_change_api.php?action=acknowledge_alarm&alarm_id=${alarmId}`);
                    const data = await response.json();
                    
                    if (data.success) {
                        showNotification('Alarm bilgi dahilinde kapatıldı', 'success');
                        loadPortAlarms(currentAlarmFilter);
                    } else {
                        showNotification(data.error || 'Hata oluştu', 'error');
                    }
                } catch (error) {
                    console.error('Error acknowledging alarm:', error);
                    showNotification('İşlem başarısız oldu', 'error');
                }
            };
            
            window.silenceIndexAlarm = async function(alarmId) {
                const duration = prompt('Kaç saat sesize alınsın?\n\n1 = 1 saat\n4 = 4 saat\n24 = 24 saat\n168 = 1 hafta', '1');
                
                if (!duration) {
                    return;
                }
                
                try {
                    const response = await fetch(`api/port_change_api.php?action=silence_alarm&alarm_id=${alarmId}&duration=${duration}`);
                    const data = await response.json();
                    
                    if (data.success) {
                        showNotification(`Alarm ${duration} saat sesize alındı`, 'success');
                        loadPortAlarms(currentAlarmFilter);
                    } else {
                        showNotification(data.error || 'Hata oluştu', 'error');
                    }
                } catch (error) {
                    console.error('Error silencing alarm:', error);
                    showNotification('İşlem başarısız oldu', 'error');
                }
            };

            window.bulkAcknowledgeAllAlarms = async function() {
                const items = document.querySelectorAll('#alarms-list-container .alarm-list-item');
                if (!items.length) {
                    showNotification('Kapatılacak alarm bulunamadı', 'info');
                    return;
                }
                const count = items.length;
                if (!confirm(`Görüntülenen ${count} adet alarm "Bilgi Dahilinde" olarak kapatılacak. Onaylıyor musunuz?`)) {
                    return;
                }
                const alarmIds = Array.from(items).map(el => el.dataset.alarmId).filter(Boolean);
                if (!alarmIds.length) return;

                try {
                    const btn = document.getElementById('bulk-close-alarms-btn');
                    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Kapatılıyor...'; }

                    const formData = new FormData();
                    formData.append('action', 'bulk_acknowledge');
                    formData.append('alarm_ids', JSON.stringify(alarmIds.map(Number)));
                    formData.append('ack_type', 'known_change');
                    formData.append('note', 'Toplu kapatma');

                    const response = await fetch('api/port_change_api.php', { method: 'POST', body: formData });
                    const data = await response.json();

                    if (data.success) {
                        showNotification(`${data.acknowledged_count} alarm başarıyla kapatıldı`, 'success');
                        loadPortAlarms(currentAlarmFilter);
                    } else {
                        showNotification(data.error || 'Hata oluştu', 'error');
                    }
                } catch (error) {
                    console.error('Error bulk acknowledging alarms:', error);
                    showNotification('İşlem başarısız oldu', 'error');
                } finally {
                    const btn = document.getElementById('bulk-close-alarms-btn');
                    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-check-double"></i> Tümünü Kapat'; }
                }
            };

            window.showIndexAlarmDetails = async function(alarmId) {
                try {
                    const response = await fetch(`api/port_change_api.php?action=get_alarm_details&alarm_id=${alarmId}`);
                    const data = await response.json();
                    
                    if (data.success && data.alarm) {
                        const alarm = data.alarm;
                        const details = `
Alarm Detayları:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Cihaz: ${alarm.device_name}
Port: ${alarm.port_number || 'N/A'}
Tip: ${alarm.alarm_type}
Seviye: ${alarm.severity}

Mesaj: ${maskIPs(alarm.message)}

İlk Görülme: ${alarm.first_occurrence ? new Date(alarm.first_occurrence.replace(' ','T')).toLocaleString('tr-TR') : 'N/A'}
Son Görülme: ${alarm.last_occurrence ? new Date(alarm.last_occurrence.replace(' ','T')).toLocaleString('tr-TR') : 'N/A'}
Tekrar Sayısı: ${alarm.occurrence_count}

${alarm.old_value && alarm.new_value ? `Değişiklik:\n${alarm.old_value} → ${alarm.new_value}\n\n` : ''}
${alarm.acknowledged_at ? `Onaylandı: ${alarm.acknowledged_at} (${alarm.acknowledged_by})\n` : ''}
${alarm.is_silenced ? `Sesize Alındı: ${alarm.silence_until} saate kadar\n` : ''}
                        `;
                        alert(details);
                    } else {
                        showNotification('Alarm detayları alınamadı', 'error');
                    }
                } catch (error) {
                    console.error('Error fetching alarm details:', error);
                    showNotification('İşlem başarısız oldu', 'error');
                }
            };
            
            // Show notification toast
            function showNotification(message, type = 'info') {
                const toast = document.createElement('div');
                toast.className = 'notification-toast';
                
                // Color-coded by type
                const colors = {
                    'success': '#27ae60',  // Green
                    'error': '#e74c3c',    // Red
                    'info': '#3498db',     // Blue
                    'warning': '#f39c12'   // Orange
                };
                
                toast.style.cssText = `
                    position: fixed;
                    top: 80px;
                    right: 20px;
                    background: ${colors[type] || colors.info};
                    color: white;
                    padding: 15px 25px;
                    border-radius: 8px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                    z-index: 10001;
                    font-size: 14px;
                    font-weight: 500;
                    animation: slideInRight 0.3s ease-out;
                    max-width: 350px;
                `;
                
                toast.textContent = message;
                document.body.appendChild(toast);
                
                // Auto-dismiss after 4 seconds
                setTimeout(() => {
                    toast.style.animation = 'slideOutRight 0.3s ease-in';
                    setTimeout(() => toast.remove(), 300);
                }, 4000);
            }
            
            // Alarm filter buttons
            document.querySelectorAll('.alarm-filter-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    // Update active button
                    document.querySelectorAll('.alarm-filter-btn').forEach(b => {
                        b.classList.remove('btn-primary');
                        b.classList.add('btn-secondary');
                    });
                    this.classList.remove('btn-secondary');
                    this.classList.add('btn-primary');
                    
                    // Update filter
                    currentAlarmFilter = this.dataset.filter;
                    loadPortAlarms(currentAlarmFilter);
                });
            });
            
            // Load alarms on init
            loadPortAlarms();
            
            // Refresh alarms every 30 seconds
            setInterval(() => {
                if (document.getElementById('port-alarms-modal').classList.contains('active')) {
                    loadPortAlarms(currentAlarmFilter);
                } else {
                    // Just update badge count without reloading modal
                    fetch('api/port_change_api.php?action=get_active_alarms')
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                updateAlarmBadge(data.alarms.length);
                                window._portAlarmsMap = {};
                                (data.alarms || []).forEach(a => {
                                    if (a.device_id && a.port_number) {
                                        window._portAlarmsMap[`${a.device_id}:${a.port_number}`] = true;
                                    }
                                });
                            }
                        })
                        .catch(err => console.error('Error updating alarm badge:', err));
                }
            }, 30000);
            
            // Test fonksiyonlarını global yap
            window.testFiberPanelAdd = async function() {
                const testData = {
                    rackId: 1,
                    panelLetter: 'A',
                    totalFibers: 24,
                    positionInRack: 15,
                    description: 'Test fiber panel'
                };
                
                try {
                    const response = await fetch('actions/saveFiberPanel.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(testData)
                    });
                    
                    const result = await response.json();
                    console.log('Test result:', result);
                    
                    if (result.success) {
                        alert('Fiber panel başarıyla eklendi!');
                        await loadData();
                        loadRacksPage();
                    } else {
                        alert('Hata: ' + result.message);
                    }
                } catch (error) {
                    console.error('Test error:', error);
                    alert('Test hatası: ' + error.message);
                }
            };
            
            window.listFiberPanels = function() {
                console.log('Fiber Paneller:');
                if (fiberPanels && fiberPanels.length > 0) {
                    fiberPanels.forEach(panel => {
                        const rack = racks.find(r => r.id === panel.rack_id);
                        console.log(`- ${panel.panel_letter}: ${panel.total_fibers} fiber, Slot ${panel.position_in_rack}, Rack: ${rack ? rack.name : 'Unknown'}`);
                    });
                } else {
                    console.log('Henüz fiber panel yok.');
                }
            };

            // Hub test fonksiyonu
            window.testHubFunction = async function() {
                const testData = {
                    switchId: 1,
                    port: 1,
                    isHub: 1,
                    hubName: "Test Hub",
                    connections: JSON.stringify([
                        {device: "Test Cihaz 1", ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:ff", type: "DEVICE"},
                        {device: "Test Cihaz 2", ip: "192.168.1.11", mac: "aa:bb:cc:dd:ee:fe", type: "AP"}
                    ]),
                    type: "HUB"
                };
                
                try {
                    const response = await fetch('actions/updatePort.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(testData)
                    });
                    
                    const result = await response.json();
                    console.log('Test result:', result);
                    
                    if (result.status === 'ok') {
                        alert('Hub port testi başarılı!');
                        await loadData();
                    } else {
                        alert('Hata: ' + result.message);
                    }
                } catch (error) {
                    console.error('Hub test error:', error);
                    alert('Test hatası: ' + error.message);
                }
            };
        }

        // ============================================
        // SNMP DATA FUNCTIONS
        // ============================================
        
        // Handle URL parameters (e.g., switch_id from admin.php)
        function handleURLParameters() {
            const urlParams = new URLSearchParams(window.location.search);
            const switchId = urlParams.get('switch_id');
            const switchName = urlParams.get('switch');
            const portNumber = urlParams.get('port') || urlParams.get('highlight_port');
            
            if (switchId) {
                // Find the switch by ID
                const switchToEdit = switches.find(sw => sw.id == switchId);
                if (switchToEdit) {
                    // Open switch modal for editing
                    setTimeout(() => {
                        openSwitchModal(switchToEdit);
                    }, 500); // Small delay to ensure data is loaded
                } else {
                    showToast('Switch bulunamadı: ID ' + switchId, 'error');
                }
                
                // Clean URL without reloading page
                const cleanUrl = window.location.pathname;
                window.history.replaceState({}, document.title, cleanUrl);
            } else if (switchName) {
                // Navigate to switch detail by name (used by reports "Porta Git")
                const sw = switches.find(s => s.name === switchName);
                if (sw) {
                    switchPage('switches');
                    setTimeout(() => {
                        showSwitchDetail(sw, portNumber ? parseInt(portNumber) : null);
                    }, 300);
                } else {
                    showToast('Switch bulunamadı: ' + switchName, 'error');
                }
                
                // Clean URL without reloading page
                const cleanUrl = window.location.pathname;
                window.history.replaceState({}, document.title, cleanUrl);
            }
        }

        document.addEventListener('DOMContentLoaded', init);
        
        // Handle URL parameters after init
        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(handleURLParameters, 1000); // Wait for data to load
        });
        
        // Listen for messages from iframe (e.g., port_alarms.php, reports.php)
        window.addEventListener('message', function(event) {
            // Security check - you may want to add origin validation
            if (event.data && event.data.action === 'navigateToPort') {
                const switchName = event.data.switchName;
                const portNumber = event.data.portNumber;
                
                console.log('Received navigateToPort message:', switchName, portNumber);
                
                const switchToOpen = switches.find(s => s.name === switchName);
                if (switchToOpen) {
                    // Show the detail panel as a floating overlay without
                    // navigating away from the currently active page (e.g. reports)
                    const detailPanel = document.getElementById('detail-panel');
                    detailPanel.classList.add('from-reports');
                    // Set full-page link so user can open in a new tab
                    const fullPageLink = document.getElementById('detail-fullpage-link');
                    if (fullPageLink) {
                        fullPageLink.href = `index.php?switch_id=${switchToOpen.id}&highlight_port=${portNumber}`;
                    }
                    showSwitchDetail(switchToOpen, portNumber);
                } else {
                    showToast('Switch bulunamadı: ' + switchName, 'error');
                }
            }
        });
    </script>
	<script src="index_fiber_bridge_patch.js"></script>
    <!-- Port Change Highlighting and VLAN Display Module -->
    <script src="port-change-highlight.js?v=<?php echo time(); ?>"></script>
    
    <!-- Real-Time Updates for Alarms and Port Status -->
    <script>
    (function() {
        'use strict';
        
        let lastAlarmCheck = new Date().toISOString().slice(0, 19).replace('T', ' ');
        let updateInterval = null;
        let alarmBadge = null;
        
        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
        
        // Initialize real-time updates
        function initRealTimeUpdates() {
            console.log('🔄 Initializing real-time updates...');
            
            // Find or create alarm badge
            alarmBadge = document.querySelector('.alarm-badge') || createAlarmBadge();
            
            // Start polling every 5 seconds
            updateInterval = setInterval(checkForUpdates, 5000);
            
            // Initial check
            checkForUpdates();
        }
        
        // Create alarm badge if it doesn't exist
        function createAlarmBadge() {
            const alarmBtn = document.querySelector('[onclick*="toggleAlarmModal"]');
            if (alarmBtn && !alarmBtn.querySelector('.alarm-badge')) {
                const badge = document.createElement('span');
                badge.className = 'alarm-badge';
                badge.style.cssText = `
                    position: absolute;
                    top: -5px;
                    right: -5px;
                    background: #e74c3c;
                    color: white;
                    border-radius: 50%;
                    padding: 2px 6px;
                    font-size: 11px;
                    font-weight: bold;
                    display: none;
                `;
                alarmBtn.style.position = 'relative';
                alarmBtn.appendChild(badge);
                return badge;
            }
            return null;
        }
        
        // Check for updates
        async function checkForUpdates() {
            try {
                // Check for new alarms
                const response = await fetch(`api/snmp_realtime_api.php?action=check_new_alarms&last_check=${encodeURIComponent(lastAlarmCheck)}`);
                
                // Check if response is OK (status 200-299)
                if (!response.ok) {
                    if (response.status === 401) {
                        console.warn('⚠️ Session expired, please reload the page');
                        clearInterval(updateInterval);
                        return;
                    }
                    console.warn(`API returned status ${response.status}`);
                    return;
                }
                
                // Get response text first to handle empty responses
                const text = await response.text();
                if (!text || text.trim() === '') {
                    return; // Empty response, nothing to process
                }
                
                // Parse JSON safely
                let data;
                try {
                    data = JSON.parse(text);
                } catch (jsonError) {
                    console.error('Invalid JSON response from API:', text.substring(0, 200));
                    return;
                }
                
                if (data.success) {
                    // Update last check timestamp
                    lastAlarmCheck = data.timestamp;
                    
                    // Update alarm count
                    updateAlarmCount();
                    
                    // Show notifications for new alarms
                    if (data.has_new && data.new_alarms.length > 0) {
                        console.log(`🚨 ${data.new_alarms.length} new alarm(s) detected`);
                        
                        data.new_alarms.forEach(alarm => {
                            showAlarmNotification(alarm);
                            
                            // Refresh alarm modal if it's open
                            if (document.getElementById('alarm-modal')?.classList.contains('active')) {
                                loadPortAlarms('all');
                            }
                        });
                    }
                }
            } catch (error) {
                console.error('Real-time update error:', error);
            }
        }
        
        // Update alarm count badge
        async function updateAlarmCount() {
            try {
                const response = await fetch('api/snmp_realtime_api.php?action=get_alarm_count');
                
                // Check if response is OK
                if (!response.ok) {
                    if (response.status !== 401) { // Don't log 401s (handled in checkForUpdates)
                        console.warn(`Alarm count API returned status ${response.status}`);
                    }
                    return;
                }
                
                // Get response text first
                const text = await response.text();
                if (!text || text.trim() === '') {
                    return;
                }
                
                // Parse JSON safely
                let data;
                try {
                    data = JSON.parse(text);
                } catch (jsonError) {
                    console.error('Invalid JSON in alarm count response:', text.substring(0, 100));
                    return;
                }
                
                if (data.success && data.counts) {
                    const total = parseInt(data.counts.total) || 0;
                    
                    if (alarmBadge) {
                        if (total > 0) {
                            alarmBadge.textContent = total;
                            alarmBadge.style.display = 'block';
                        } else {
                            alarmBadge.style.display = 'none';
                        }
                    }
                }
            } catch (error) {
                console.error('Error updating alarm count:', error);
            }
        }
        
        // Show alarm notification
        function showAlarmNotification(alarm) {
            // Desktop notification
            if ('Notification' in window && Notification.permission === 'granted') {
                const title = `🚨 ${alarm.severity} Alarm`;
                const body = `${alarm.device_name} - ${maskIPs(alarm.message)}`;
                
                const notification = new Notification(title, {
                    body: body,
                    icon: '/favicon.ico',
                    badge: '/favicon.ico',
                    tag: `alarm-${alarm.id}`,
                    requireInteraction: alarm.severity === 'CRITICAL',
                    silent: false
                });
                
                notification.onclick = function() {
                    window.focus();
                    // Navigate to alarm if we have device and port info
                    if (alarm.device_id && alarm.port_number && typeof navigateToAlarmPort === 'function') {
                        navigateToAlarmPort(alarm.device_id, alarm.port_number, alarm.device_name, alarm.device_ip);
                    }
                    notification.close();
                };
                
                // Auto-close after 10 seconds (except CRITICAL)
                if (alarm.severity !== 'CRITICAL') {
                    setTimeout(() => notification.close(), 10000);
                }
            }
            
            // Visual notification on page (toast)
            showToastNotification(alarm);
        }
        
        // Show toast notification on page
        function showToastNotification(alarm) {
            const toast = document.createElement('div');
            toast.className = 'alarm-toast';
            toast.style.cssText = `
                position: fixed;
                top: 80px;
                right: 20px;
                background: ${getSeverityColor(alarm.severity)};
                color: white;
                padding: 15px 20px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                z-index: 10000;
                max-width: 400px;
                cursor: pointer;
                animation: slideInRight 0.3s ease-out;
            `;
            
            toast.innerHTML = `
                <div style="display: flex; align-items: start; gap: 10px;">
                    <i class="fas fa-exclamation-triangle" style="font-size: 20px; margin-top: 2px;"></i>
                    <div>
                        <div style="font-weight: bold; margin-bottom: 5px;">
                            ${alarm.severity} - ${alarm.device_name}
                        </div>
                        <div style="font-size: 13px; opacity: 0.9;">
                            ${maskIPs(alarm.message)}
                        </div>
                    </div>
                </div>
            `;
            
            toast.onclick = function() {
                if (alarm.device_id && alarm.port_number && typeof navigateToAlarmPort === 'function') {
                    navigateToAlarmPort(alarm.device_id, alarm.port_number, alarm.device_name, alarm.device_ip);
                }
                toast.remove();
            };
            
            document.body.appendChild(toast);
            
            // Auto-remove after 8 seconds
            setTimeout(() => {
                toast.style.animation = 'slideOutRight 0.3s ease-in';
                setTimeout(() => toast.remove(), 300);
            }, 8000);
        }
        
        // Get severity color
        function getSeverityColor(severity) {
            const colors = {
                'CRITICAL': '#8B0000',
                'HIGH': '#e74c3c',
                'MEDIUM': '#f39c12',
                'LOW': '#3498db'
            };
            return colors[severity] || '#95a5a6';
        }
        
        // Add CSS animations
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideInRight {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            @keyframes slideOutRight {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(400px);
                    opacity: 0;
                }
            }
            
            @keyframes pulse {
                0%, 100% {
                    box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.7);
                }
                50% {
                    box-shadow: 0 0 0 20px rgba(59, 130, 246, 0);
                }
            }

            @keyframes port-highlight-blink {
                0%   { outline: 3px solid #facc15; box-shadow: 0 0 0 0 rgba(250,204,21,0.8); transform: scale(1); }
                25%  { outline: 3px solid #facc15; box-shadow: 0 0 10px 6px rgba(250,204,21,0.6); transform: scale(1.18); }
                50%  { outline: 3px solid #facc15; box-shadow: 0 0 0 0 rgba(250,204,21,0.8); transform: scale(1); }
                75%  { outline: 3px solid #facc15; box-shadow: 0 0 10px 6px rgba(250,204,21,0.6); transform: scale(1.18); }
                100% { outline: none; box-shadow: none; transform: scale(1); }
            }
            
            .alarm-toast:hover {
                transform: scale(1.02);
                transition: transform 0.2s;
            }
        `;
        document.head.appendChild(style);
        
        // Start when page loads
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initRealTimeUpdates);
        } else {
            initRealTimeUpdates();
        }
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', function() {
            if (updateInterval) {
                clearInterval(updateInterval);
            }
        });
        
        console.log('✅ Real-time alarm system initialized');
    })();
    </script>
</body>
</html>