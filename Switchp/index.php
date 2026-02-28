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
            display: flex;
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

        .hub-port .port-type {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%) !important;
            color: white !important;
        }

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
    font-size: 0.7rem;
    font-weight: 700;
    cursor: pointer;
    z-index: 6;
    box-shadow: 0 2px 6px rgba(0,0,0,0.35);
    transition: transform 0.12s ease;
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
        
        .port-device {
            font-size: 0.75rem;
            color: var(--text-light);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            margin-bottom: 5px;
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
            <i class="fas fa-server"></i>
            <h1>RackPro Manager</h1>
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
            <button class="nav-item" data-page="device-import">
                <i class="fas fa-file-import"></i>
                <span>Device Import</span>
            </button>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">SNMP Admin</div>
            <button class="nav-item" id="nav-snmp-admin" onclick="window.open('admin.php', '_blank')" style="background: rgba(139, 92, 246, 0.1); border: 1px solid rgba(139, 92, 246, 0.3);">
                <i class="fas fa-cogs"></i>
                <span>SNMP Admin Panel</span>
            </button>
        </div>
        
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
                <div class="stat-card">
                    <i class="fas fa-server stat-icon"></i>
                    <div class="stat-value" id="stat-total-switches">0</div>
                    <div class="stat-label">Toplam Switch</div>
                </div>
                <div class="stat-card">
                    <i class="fas fa-plug stat-icon"></i>
                    <div class="stat-value" id="stat-active-ports">0</div>
                    <div class="stat-label">Aktif Port</div>
                </div>
                <div class="stat-card">
                    <i class="fas fa-cube stat-icon"></i>
                    <div class="stat-value" id="stat-total-racks">0</div>
                    <div class="stat-label">Rack Kabin</div>
                </div>
                <div class="stat-card">
                    <i class="fas fa-th-large stat-icon"></i>
                    <div class="stat-value" id="stat-total-panels">0</div>
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
                    </div>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button class="btn btn-secondary" onclick="window.open('admin.php', '_blank')">
                        <i class="fas fa-cogs"></i> Yönetim Paneli
                    </button>
                </div>
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
                    <span>Network Topolojisi</span>
                </div>
            </div>
            
            <div class="detail-panel">
                <div id="topology-container" style="height: 600px; background: var(--dark); border-radius: 15px; padding: 20px; overflow: auto;">
                    <div style="text-align: center; padding: 100px; color: var(--text-light);">
                        <i class="fas fa-project-diagram" style="font-size: 4rem; margin-bottom: 20px; color: var(--primary);"></i>
                        <h3 style="margin-bottom: 10px;">Topoloji Görünümü</h3>
                        <p>Network topolojisi görselleştirmesi burada gösterilecek</p>
                    </div>
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
            </div>
            
            <!-- Port Alarms Component (same-origin trusted PHP file, no sandbox needed) -->
            <iframe src="port_alarms.php" 
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
            </div>
            
            <!-- Device Import Component (same-origin trusted PHP file, no sandbox needed) -->
            <iframe src="device_import.php" 
                    style="width: 100%; height: calc(100vh - 150px); border: none; border-radius: 15px; background: var(--dark);"
                    onload="this.style.display='block'"
                    onerror="this.innerHTML='<div style=padding:20px;text-align:center;color:red;>Error loading device import page</div>'">
            </iframe>
        </div>
    </div>
    
    <!-- Toast Container -->
    <div class="toast-container" id="toast-container"></div>
    
    <!-- Auto Backup Indicator -->
    <div class="backup-indicator" id="backup-indicator" title="Son yedekleme">
        <i class="fas fa-database"></i>
    </div>
    
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
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Hub Port Yönetimi</h3>
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
                        <label class="form-label" style="display:flex;align-items:center;gap:8px;">
                            Bağlantı Türü
                            <span id="modal-vlan-badge" style="display:none;font-size:11px;font-weight:600;padding:2px 8px;border-radius:10px;background:#0d6efd;color:#fff;letter-spacing:.5px;"></span>
                        </label>
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
                    <label class="form-label">
                        Cihaz Adı/Açıklama
                    </label>
                    <input type="text" id="port-device" class="form-control" placeholder="Ör: OTOMASYON">
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">IP Adresi</label>
                        <input type="text" id="port-ip" class="form-control" placeholder="Ör: 172.18.120.37">
                    </div>
                    <div class="form-group">
                        <label class="form-label">MAC Adresi</label>
                        <input type="text" id="port-mac" class="form-control" placeholder="Ör: 00:18:bb:02:8a:47">
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
                              placeholder="Ek bağlantı bilgileri, oda/cihaz notları vb."></textarea>
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
		
		// Veri yapıları
        let switches = [];
        let portConnections = {};
        let racks = [];
        let patchPanels = [];
        let fiberPanels = [];
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
        const backupIndicator = document.getElementById('backup-indicator');
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
                        
                        <!-- Switch Seçimi -->
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
            
            // Rack'teki switch'leri yükle
            loadSwitchesForRack(panel.rack_id, panelType, currentSwitch ? currentSwitch.id : null);
            
            // Form submit
            document.getElementById('panel-port-edit-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                await savePanelPortConnection();
            });
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
                    ${port.connection_info_preserved ? `
                        <div style="margin-top: 10px; padding: 10px; background: rgba(59, 130, 246, 0.1); border-radius: 5px;">
                            <strong>Connection Bilgisi:</strong><br>
                            <small>${port.connection_info_preserved}</small>
                        </div>
                    ` : ''}
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

  // filter by rack if provided
  let list = switches || [];
  if (rackId !== null && rackId !== undefined) {
    list = list.filter(s => Number(s.rack_id) === Number(rackId));
  }

  list.forEach(sw => {
    const opt = document.createElement('option');
    opt.value = sw.id;
    opt.textContent = `${sw.name} (${sw.ports} port)`;
    opt.dataset.ports = sw.ports;
    opt.dataset.fiberStart = Math.max(1, sw.ports - 3); // last 4 ports are fiber
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
          const fiberStart = Math.max(1, sw.ports - 3);
          for (let p = fiberStart; p <= sw.ports; p++) {
            const o = document.createElement('option'); o.value = p; o.textContent = `Port ${p} (Fiber)`;
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
          const fiberStart = Math.max(1, sw.ports - 3);
          for (let p = fiberStart; p <= sw.ports; p++) {
            const o = document.createElement('option'); o.value = p; o.textContent = `Port ${p} (Fiber)`;
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
      const resp = await fetch('saveFiberPortConnection.php', {
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
            const targetSwitchId = document.getElementById('edit-target-switch').value;
            const targetPort = document.getElementById('edit-target-port').value;
            
            if (!targetSwitchId || !targetPort) {
                showToast('Lütfen switch ve port seçin', 'warning');
                return;
            }
            
            try {
                showLoading();
                
                const response = await fetch('savePanelToSwitchConnection.php', {
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
                
                const response = await fetch('disconnectPanelPort.php', {
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
         // REPLACE: the existing buildTooltipContent(...) function inside the tooltip IIFE with this block

function buildTooltipContent(el) {
  const port = el.getAttribute('data-port') || el.dataset.port || (el.querySelector('.port-number') ? el.querySelector('.port-number').textContent.trim() : '');
  const device = el.getAttribute('data-device') || el.dataset.device || el.querySelector('.port-device')?.textContent?.trim() || '';
  const type = el.getAttribute('data-type') || el.dataset.type || el.querySelector('.port-type')?.textContent?.trim() || '';
  const ip = el.getAttribute('data-ip') || el.dataset.ip || '';
  const mac = el.getAttribute('data-mac') || el.dataset.mac || '';
  const connPreserved = el.getAttribute('data-connection') || el.dataset.connection || '';
  const connJson = el.getAttribute('data-connection-json') || el.dataset.connectionJson || '';
  const multi = el.getAttribute('data-multiple') || el.dataset.multiple || '';

  let html = `<div style="font-weight:700;margin-bottom:6px;">Port: ${escapeHtml(port)} ${type ? '(' + escapeHtml(type) + ')' : ''}</div>`;
  if (device) html += `<div style="margin-bottom:4px;"><strong>Cihaz:</strong> ${escapeHtml(device)}</div>`;
  if (ip) html += `<div style="margin-bottom:4px;"><strong>IP:</strong> <span style="font-family:monospace">${escapeHtml(ip)}</span></div>`;
  if (mac) html += `<div style="margin-bottom:4px;"><strong>MAC:</strong> <span style="font-family:monospace">${escapeHtml(mac)}</span></div>`;

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
        html += `<div style="margin-bottom:6px;"><strong>Hub Cihazları:</strong></div>`;
        arr.slice(0,6).forEach((it, idx) => {
          const name = it.device || it.name || it;
          html += `<div style="font-size:0.85rem;"><strong>${idx+1}:</strong> ${escapeHtml(name)}${it.ip ? ` • ${escapeHtml(it.ip)}` : ''}${it.mac ? ` • ${escapeHtml(it.mac)}` : ''}</div>`;
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
          html += `<div style="font-size:0.85rem;"><strong>${idx+1}:</strong> ${escapeHtml(it.device || it.name || '')}${it.ip ? ' • ' + escapeHtml(it.ip) : ''}</div>`;
        });
      } else {
        html += `<div style="font-size:0.85rem;">${escapeHtml(JSON.stringify(parsed))}</div>`;
      }
    } catch(e) {
      html += `<div style="font-size:0.85rem;">${escapeHtml(connJson)}</div>`;
    }
  } else if (connPreserved) {
    html += `<div style="font-size:0.9rem;">${escapeHtml(connPreserved)}</div>`;
  } else {
    html += `<div style="font-size:0.85rem; color:var(--text-light);">Bağlantı bilgisi yok</div>`;
  }

  html += `</div>`;
  return html;
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
                        usedSlots.add(parseInt(sw.position_in_rack));
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
                    usedSlots.add(parseInt(sw.position_in_rack));
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
            
            try {
                // Basit versiyon
                let html = `
                    <div style="text-align: center; margin-bottom: 20px;">
                        <div style="font-size: 2rem; color: #f59e0b; margin-bottom: 10px;">
                            <i class="fas fa-network-wired"></i>
                        </div>
                        <h3 style="color: var(--text);">${connection.hub_name || 'Hub Port'}</h3>
                        <div style="color: var(--text-light); margin-bottom: 20px;">
                            Port ${portNo}
                        </div>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h4 style="color: var(--primary); margin-bottom: 10px;">Bağlantı Bilgileri</h4>
                        <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px;">
                            <div style="margin-bottom: 10px;">
                                <div style="color: var(--text-light); font-size: 0.9rem;">IP Adresleri:</div>
                                <div style="color: var(--text); font-family: monospace; padding: 10px; background: rgba(16, 185, 129, 0.1); border-radius: 8px;">
                                    ${connection.ip || 'Yok'}
                                </div>
                            </div>
                            <div>
                                <div style="color: var(--text-light); font-size: 0.9rem;">MAC Adresleri:</div>
                                <div style="color: var(--text); font-family: monospace; padding: 10px; background: rgba(59, 130, 246, 0.1); border-radius: 8px;">
                                    ${connection.mac || 'Yok'}
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 30px; display: flex; gap: 10px;">
                        <button class="btn btn-secondary" style="flex: 1;" onclick="closeHubModal()">
                            <i class="fas fa-times"></i> Kapat
                        </button>
                        <button class="btn btn-warning" style="flex: 1;" 
                                onclick="editHubPort(${switchId}, ${portNo})">
                            <i class="fas fa-edit"></i> Düzenle
                        </button>
                    </div>
                `;
                
                content.innerHTML = html;
                modal.classList.add('active');
                
            } catch (error) {
                console.error('Hub detay yükleme hatası:', error);
                content.innerHTML = `
                    <div style="text-align: center; padding: 40px; color: #ef4444;">
                        <i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 15px;"></i>
                        <p>Hub bilgileri yüklenemedi</p>
                    </div>
                `;
            }
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
                hubIcon.textContent = 'H';
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
                
                const response = await fetch('saveFiberPanel.php', {
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
                document.getElementById('switch-name').value = switchToEdit.name;
                document.getElementById('switch-brand').value = switchToEdit.brand || '';
                document.getElementById('switch-model').value = switchToEdit.model || '';
                document.getElementById('switch-ports').value = switchToEdit.ports;
                document.getElementById('switch-status').value = switchToEdit.status;
                document.getElementById('switch-ip').value = switchToEdit.ip || '';
                
                if (switchToEdit.rack_id) {
                    rackSelect.value = switchToEdit.rack_id;
                    // Slot listesini güncelle
                    updateAvailableSlots(switchToEdit.rack_id, 'switch', switchToEdit.position_in_rack);
                }
            } else {
                title.textContent = 'Yeni Switch Ekle';
                document.getElementById('switch-id').value = '';
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
            const isFiberPort = portNumber > (sw.ports - 4);
            
            if (portNumber) {
                document.getElementById('port-number').value = portNumber;
                document.getElementById('port-no-display').value = `Port ${portNumber} ${isFiberPort ? '(Fiber)' : '(Ethernet)'}`;
            }
            
            // Mevcut bağlantı bilgilerini yükle
            if (existingConnection) {
                modal.querySelector('.modal-title').textContent = 'Port ' + portNumber + ' Düzenle';
                
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
                modal.querySelector('.modal-title').textContent = 'Port ' + portNumber + ' Ekle';
                document.getElementById('port-type').value = isFiberPort ? 'FIBER' : 'ETHERNET';
                const vlanBadgeNew = document.getElementById('modal-vlan-badge');
                if (vlanBadgeNew) vlanBadgeNew.style.display = 'none';
            }
            
            // Panel tipi değişim eventi
            setupPanelTypeChangeEvent(sw.rack_id, isFiberPort);
            
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
                
                const response = await fetch('getData.php?action=updatePortConnection', {
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
                const response = await fetch(`device_import_api.php?action=get&mac=${encodeURIComponent(mac)}`);
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
                
                const response = await fetch('getData.php');
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
                
                console.log('Veriler yüklendi:', {
                    switchCount: switches.length,
                    rackCount: racks.length,
                    patchPanelCount: patchPanels.length,
                    patchPortCount: Object.keys(patchPorts).length,
                    fiberPanelCount: fiberPanels.length,
                    fiberPortCount: Object.keys(fiberPorts).length
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
                const response = await fetch('saveSwitch.php', {
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
                const response = await fetch('saveSwitch.php', {
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
                const response = await fetch(`delete.php?type=switch&id=${switchId}`);
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
                const response = await fetch('saveRack.php', {
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
                const response = await fetch('saveRack.php', {
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
                const response = await fetch(`delete.php?type=rack&id=${rackId}`);
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
                
                const response = await fetch('savePortWithPanel.php', {
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
                
                const response = await fetch('updatePort.php', {
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
                const resp = await fetch('snmp_data_api.php?action=php_vlan_sync');
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
                const resp = await fetch('snmp_data_api.php?action=php_vlan_sync');
                const res  = await resp.json();
                if (res.success && res.updated_ports > 0) {
                    await loadData();
                    if (selectedSwitch) showSwitchDetail(selectedSwitch);
                }
            } catch (e) {
                // Silently ignore errors in background sync
            }
        }
        setInterval(phpVlanSyncSilent, 120000);

        async function resetAllPorts(switchId) {
            if (!confirm('Bu switch\'teki TÜM port bağlantılarını boşa çekmek istediğinize emin misiniz?')) return;
            
            try {
                showLoading();
                
                const response = await fetch('updatePort.php', {
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
                
                let activePorts = 0;
                
                Object.values(portConnections).forEach(connections => {
                    activePorts += connections.filter(c => c.is_active).length;
                });
                
                // Elementleri güncelle
                document.getElementById('stat-total-switches').textContent = totalSwitches;
                document.getElementById('stat-total-racks').textContent = totalRacks;
                document.getElementById('stat-total-panels').textContent = totalPatchPanels + totalFiberPanels;
                document.getElementById('stat-active-ports').textContent = activePorts;
                
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
            if (lastBackupTime) {
                const time = new Date(lastBackupTime);
                const now = new Date();
                const diff = now - time;
                const minutes = Math.floor(diff / 60000);
                
                backupIndicator.classList.add('active');
                backupIndicator.title = `Son yedekleme: ${minutes} dakika önce`;
            }
        }

        function loadDashboard() {
            const container = document.getElementById('dashboard-racks');
            if (!container) return;
            
            container.innerHTML = '';
            
            racks.forEach(rack => {
                const rackSwitches = switches.filter(s => s.rack_id === rack.id);
                const rackPatchPanels = patchPanels.filter(p => p.rack_id === rack.id);
                const rackFiberPanels = fiberPanels.filter(fp => fp.rack_id === rack.id);
                
                // İlk 10 slotu göster (Dashboard için)
                const rackCard = document.createElement('div');
                rackCard.className = 'rack-card dashboard-rack';
                rackCard.innerHTML = `
                    <div class="rack-3d">
                        <div class="rack-slots">
                            ${Array.from({ length: 10 }, (_, i) => {
                                const slotNumber = i + 1;
                                let slotClass = 'rack-slot empty';
                                
                                // İlk 10 slot için kontrol et
                                const sw = rackSwitches.find(s => s.position_in_rack == slotNumber);
                                const panel = rackPatchPanels.find(p => p.position_in_rack == slotNumber);
                                const fiberPanel = rackFiberPanels.find(fp => fp.position_in_rack == slotNumber);
                                
                                if (sw) {
                                    slotClass = 'rack-slot switch filled';
                                } else if (panel) {
                                    slotClass = 'rack-slot patch-panel filled';
                                } else if (fiberPanel) {
                                    slotClass = 'rack-slot fiber-panel filled';
                                }
                                
                                return `<div class="${slotClass}"></div>`;
                            }).join('')}
                        </div>
                    </div>
                    <div class="rack-header">
                        <div class="rack-title">${rack.name}</div>
                        <div class="rack-switches">
                            ${rackSwitches.length} SW / ${rackPatchPanels.length} P / ${rackFiberPanels.length} F
                        </div>
                    </div>
                    <div class="rack-info">
                        <div class="rack-location">
                            <i class="fas fa-map-marker-alt"></i>
                            <span>${rack.location}</span>
                        </div>
                        <div>${rack.slots || 42} Slot</div>
                    </div>
                    ${rackSwitches.length > 0 ? `
                        <div class="rack-switch-preview">
                            ${rackSwitches.slice(0, 3).map(sw => 
                                `<div class="preview-switch">${sw.name}</div>`
                            ).join('')}
                            ${rackSwitches.length > 3 ? 
                                `<div class="preview-switch">+${rackSwitches.length - 3} daha</div>` : ''}
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
                    <button class="btn btn-sm" style="padding: 2px 8px; font-size: 0.7rem; background: rgba(245, 158, 11, 0.2);" 
                            onclick="editFiberPort(${panelId}, ${conn.port_number}, ${panel.rack_id})">
                        <i class="fas fa-edit"></i>
                    </button>
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
            <button class="btn btn-secondary" onclick="window.open('admin.php', '_blank')">
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

        window.deletePanel = async function(panelId, panelType) {
            const panel = panelType === 'patch' 
                ? patchPanels.find(p => p.id == panelId)
                : fiberPanels.find(p => p.id == panelId);
            
            if (!panel) return;
            
            if (!confirm(`${panelType === 'patch' ? 'Patch' : 'Fiber'} Panel ${panel.panel_letter} silinecek. Emin misiniz?`)) {
                return;
            }
            
            try {
                const response = await fetch(`delete.php?type=${panelType}_panel&id=${panelId}`);
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
                                <div style="display: flex; justify-content: space-between;">
                                    <span style="color: var(--text-light);">Dolu Slot:</span>
                                    <span style="color: var(--text);">${rackSwitches.length + rackPatchPanels.length + rackFiberPanels.length}/${rack.slots || 42}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <h4 style="color: var(--primary); margin-bottom: 15px;">Slot Haritası</h4>
                    <div class="rack-3d" style="height: 300px;">
                        <div class="rack-slots" style="gap: 2px;">
            `;
            
            // Tüm slotları oluştur
            for (let slotNum = 1; slotNum <= (rack.slots || 42); slotNum++) {
                let slotType = 'empty';
                let slotTitle = `Slot ${slotNum}: Boş`;
                let panelLetter = '';
                
                // Switch kontrolü
                const sw = rackSwitches.find(s => s.position_in_rack == slotNum);
                if (sw) {
                    slotType = 'switch';
                    slotTitle = `Slot ${slotNum}: ${sw.name}`;
                }
                
                // Patch panel kontrolü
                const panel = rackPatchPanels.find(p => p.position_in_rack == slotNum);
                if (panel) {
                    slotType = 'patch-panel';
                    slotTitle = `Slot ${slotNum}: Panel ${panel.panel_letter} (${panel.total_ports} Port)`;
                    panelLetter = panel.panel_letter;
                }
                
                // Fiber panel kontrolü
                const fiberPanel = rackFiberPanels.find(fp => fp.position_in_rack == slotNum);
                if (fiberPanel) {
                    slotType = 'fiber-panel';
                    slotTitle = `Slot ${slotNum}: Fiber Panel ${fiberPanel.panel_letter} (${fiberPanel.total_fibers} Fiber)`;
                    panelLetter = fiberPanel.panel_letter;
                }
                
                html += `
                    <div class="rack-slot ${slotType} filled" title="${slotTitle}">
                        <div class="slot-label">${slotType === 'switch' ? 'SW' : slotType === 'patch-panel' ? 'P' : slotType === 'fiber-panel' ? 'F' : ''}</div>
                        ${panelLetter ? `<div class="panel-label">${panelLetter}</div>` : ''}
                    </div>
                `;
            }
            
            html += `
                        </div>
                    </div>
                    
                    <div style="margin-top: 30px;">
                        <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                            <div style="display: flex; align-items: center; gap: 5px;">
                                <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); border-radius: 4px;"></div>
                                <span style="color: var(--text-light); font-size: 0.9rem;">Switch</span>
                            </div>
                            <div style="display: flex; align-items: center; gap: 5px;">
                                <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); border-radius: 4px;"></div>
                                <span style="color: var(--text-light); font-size: 0.9rem;">Patch Panel</span>
                            </div>
                            <div style="display: flex; align-items: center; gap: 5px;">
                                <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%); border-radius: 4px;"></div>
                                <span style="color: var(--text-light); font-size: 0.9rem;">Fiber Panel</span>
                            </div>
                            <div style="display: flex; align-items: center; gap: 5px;">
                                <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #10b981 0%, #059669 100%); border-radius: 4px;"></div>
                                <span style="color: var(--text-light); font-size: 0.9rem;">Dolu Slot</span>
                            </div>
                            <div style="display: flex; align-items: center; gap: 5px;">
                                <div style="width: 20px; height: 20px; background: rgba(15, 23, 42, 0.9); border: 1px solid var(--border); border-radius: 4px;"></div>
                                <span style="color: var(--text-light); font-size: 0.9rem;">Boş Slot</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <h4 style="color: var(--primary); margin-bottom: 15px;">Switch'ler (${rackSwitches.length})</h4>
                        ${rackSwitches.length > 0 ? rackSwitches.map(sw => `
                            <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px; margin-bottom: 10px; cursor: pointer;"
                                 onclick="showSwitchDetail(${JSON.stringify(sw).replace(/"/g, '&quot;')}); document.getElementById('rack-detail-modal').classList.remove('active');">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <div>
                                        <div style="font-weight: bold; color: var(--text);">${sw.name}</div>
                                        <div style="font-size: 0.85rem; color: var(--text-light); margin-top: 5px;">
                                            ${sw.brand} ${sw.model} • ${sw.ports} Port • Slot ${sw.position_in_rack || 'Belirsiz'}
                                        </div>
                                    </div>
                                    <div style="color: ${sw.status === 'online' ? '#10b981' : '#ef4444'};">
                                        <i class="fas fa-circle" style="font-size: 0.8rem;"></i>
                                    </div>
                                </div>
                            </div>
                        `).join('') : '<p style="color: var(--text-light); text-align: center;">Switch bulunmuyor</p>'}
                    </div>
                    
                    <div>
                        <h4 style="color: var(--primary); margin-bottom: 15px;">Paneller (${rackPatchPanels.length + rackFiberPanels.length})</h4>
                        ${rackPatchPanels.length > 0 ? rackPatchPanels.map(panel => `
                            <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px; margin-bottom: 10px; border-left: 4px solid #8b5cf6; cursor: pointer;"
                                 onclick="showPanelDetail(${panel.id}, 'patch'); document.getElementById('rack-detail-modal').classList.remove('active');">
                                <div style="font-weight: bold; color: var(--text);">
                                    <i class="fas fa-th-large"></i> Patch Panel ${panel.panel_letter}
                                </div>
                                <div style="font-size: 0.85rem; color: var(--text-light); margin-top: 5px;">
                                    ${panel.total_ports} Port • Slot ${panel.position_in_rack}
                                    ${panel.active_ports > 0 ? ` • ${panel.active_ports} Aktif Port` : ''}
                                    ${panel.description ? `<br>${panel.description}` : ''}
                                </div>
                            </div>
                        `).join('') : ''}
                        ${rackFiberPanels.length > 0 ? rackFiberPanels.map(panel => `
                            <div style="background: rgba(15, 23, 42, 0.5); border-radius: 10px; padding: 15px; margin-bottom: 10px; border-left: 4px solid #06b6d4; cursor: pointer;"
                                 onclick="showPanelDetail(${panel.id}, 'fiber'); document.getElementById('rack-detail-modal').classList.remove('active');">
                                <div style="font-weight: bold; color: var(--text);">
                                    <i class="fas fa-satellite-dish"></i> Fiber Panel ${panel.panel_letter}
                                </div>
                                <div style="font-size: 0.85rem; color: var(--text-light); margin-top: 5px;">
                                    ${panel.total_fibers} Fiber • Slot ${panel.position_in_rack}
                                    ${panel.description ? `<br>${panel.description}` : ''}
                                </div>
                            </div>
                        `).join('') : ''}
                        ${rackPatchPanels.length + rackFiberPanels.length === 0 ? 
                          '<p style="color: var(--text-light); text-align: center;">Panel bulunmuyor</p>' : ''}
                    </div>
                </div>
                
                <div style="margin-top: 30px; display: flex; gap: 10px; justify-content: flex-end;">
    <button class="btn btn-secondary" onclick="window.open('admin.php', '_blank')">
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
                
                const rackCard = document.createElement('div');
                rackCard.className = 'rack-card';
                rackCard.innerHTML = `
                    <div class="rack-3d">
                        <div class="rack-slots" style="gap: 2px;">
                            ${Array.from({ length: 42 }, (_, i) => {
                                const slotNumber = i + 1;
                                let slotClass = 'rack-slot empty';
                                let slotLabel = '';
                                let panelLabel = '';
                                
                                // Switch kontrolü
                                const sw = rackSwitches.find(s => s.position_in_rack == slotNumber);
                                if (sw) {
                                    slotClass = 'rack-slot switch filled';
                                    slotLabel = 'SW';
                                }
                                
                                // Patch panel kontrolü
                                const panel = rackPatchPanels.find(p => p.position_in_rack == slotNumber);
                                if (panel) {
                                    slotClass = 'rack-slot patch-panel filled';
                                    slotLabel = 'P';
                                    panelLabel = panel.panel_letter;
                                }
                                
                                // Fiber panel kontrolü
                                const fiberPanel = rackFiberPanels.find(fp => fp.position_in_rack == slotNumber);
                                if (fiberPanel) {
                                    slotClass = 'rack-slot fiber-panel filled';
                                    slotLabel = 'F';
                                    panelLabel = fiberPanel.panel_letter;
                                }
                                
                                // Boş slot kontrolü
                                const isFilled = sw || panel || fiberPanel;
                                if (!isFilled) {
                                    slotClass = 'rack-slot empty';
                                }
                                
                                return `
                                    <div class="${slotClass}" title="Slot ${slotNumber}">
                                        <div class="slot-label">${slotLabel}</div>
                                        ${panelLabel ? `<div class="panel-label">${panelLabel}</div>` : ''}
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                    <div class="rack-header">
                        <div class="rack-title">${rack.name}</div>
                        <div class="rack-switches">
                            ${rackSwitches.length} SW / ${rackPatchPanels.length} P / ${rackFiberPanels.length} F
                        </div>
                    </div>
                    <div class="rack-info">
                        <div class="rack-location">
                            <i class="fas fa-map-marker-alt"></i>
                            <span>${rack.location}</span>
                        </div>
                        <div>${rack.slots || 42} Slot</div>
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
                        <p>Yeni switch eklemek için <a href="admin.php" target="_blank" style="color:var(--primary)">Admin Paneli</a>'ni kullanın</p>
                    </div>
                `;
                return;
            }
            
            filteredSwitches.forEach(sw => {
                const connections = portConnections[sw.id] || [];
                const rack = racks.find(r => r.id === sw.rack_id);
                
                const switchCard = document.createElement('div');
                switchCard.className = 'rack-card';
                switchCard.innerHTML = `
                    <div class="switch-visual" style="margin-bottom: 0;">
                        <div class="switch-3d" style="width: 200px; height: 200px;">
                            <div class="switch-front">
                                <div class="switch-brand">${sw.brand}</div>
                                <div class="switch-name-3d" style="font-size: 1rem;">${sw.name}</div>
                                <div class="port-indicators">
                                    ${Array.from({ length: Math.min(20, sw.ports) }, (_, i) => {
                                        const portNumber = i + 1;
                                        const connection = connections.find(c => c.port === portNumber);
                                        const isConnected = connection && (
                                            (connection.ip && connection.ip.trim() !== '') || 
                                            (connection.mac && connection.mac.trim() !== '')
                                        );
                                        return `<div class="port-indicator ${isConnected ? 'active' : ''}"></div>`;
                                    }).join('')}
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="rack-header">
                        <div class="rack-title">${sw.name}</div>
                        <div class="rack-switches ${sw.status === 'online' ? 'success' : 'danger'}" 
                             style="color: ${sw.status === 'online' ? '#10b981' : '#ef4444'}">
                            <i class="fas fa-circle" style="font-size: 0.8rem;"></i> ${sw.status === 'online' ? 'Online' : 'Offline'}
                        </div>
                    </div>
                    <div class="rack-info">
                        <div>
                            <i class="fas fa-cube"></i> ${rack?.name || 'Belirsiz'}
                        </div>
                        <div>${connections.filter(c => c.device && c.device.trim() !== '' && c.type !== 'BOŞ').length}/${sw.ports} Port</div>
                    </div>
                    <div style="display: flex; gap: 10px; margin-top: 15px;">
                        <button class="btn btn-primary" style="flex: 1;" data-view-switch="${sw.id}">
                            <i class="fas fa-eye"></i> Görüntüle
                        </button>
                    </div>
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
                        showSwitchDetail(sw);
                    }
                });
            });
        }

        function loadTopologyPage() {
            console.log('Loading topology page');
        }
        
        function loadPortAlarmsPage() {
            // Port alarms page is loaded via iframe (like device-import)
            // The iframe loads port_alarms.php which handles its own display
        }

        function showSwitchDetail(sw) {
            selectedSwitch = sw;
            const detailPanel = document.getElementById('detail-panel');
            const rack = racks.find(r => r.id === sw.rack_id);
            const connections = portConnections[sw.id] || [];
            
            // Portları port numarasına göre sırala
            connections.sort((a, b) => a.port - b.port);
            
            // Update detail panel content
            document.getElementById('switch-detail-name').textContent = sw.name;
            document.getElementById('switch-detail-brand').textContent = `${sw.brand} ${sw.model}`;
            document.getElementById('switch-detail-status').innerHTML = 
                `<i class="fas fa-circle" style="color: ${sw.status === 'online' ? '#10b981' : '#ef4444'}"></i> ${sw.status === 'online' ? 'Çevrimiçi' : 'Çevrimdışı'}`;
            
            const activePorts = connections.filter(c => 
                c.device && c.device.trim() !== '' && c.type && c.type !== 'BOŞ'
            ).length;
            document.getElementById('switch-detail-ports').textContent = `${activePorts}/${sw.ports} Port Aktif`;
            
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
            for (let i = 1; i <= indicatorCount; i++) {
                const connection = connections.find(c => c.port === i);
                const isConnected = connection && connection.device && connection.device.trim() !== '' && connection.type !== 'BOŞ';
                
                const indicator = document.createElement('div');
                indicator.className = 'port-indicator';
                if (isConnected) {
                    indicator.classList.add('active');
                    indicator.title = `Port ${i}: ${connection.device}`;
                }
                indicators.appendChild(indicator);
            }
            
            // Update port grid
            const portsGrid = document.getElementById('detail-ports-grid');
            portsGrid.innerHTML = '';
            
            // Port grid'i oluştur
            for (let i = 1; i <= sw.ports; i++) {
                const connection = connections.find(c => c.port === i);
                const isConnected = connection && connection.device && connection.device.trim() !== '' && connection.type !== 'BOŞ';
                const isHub = connection && connection.is_hub == 1;
                const hasConnection = connection && connection.connection_info && connection.connection_info !== '[]' && connection.connection_info !== 'null';
                const isDown = connection && connection.is_down;
                // "VLAN X" type: port is up but VLAN is unrecognized
                const isVlanType = connection && connection.type && /^VLAN \d+$/.test(connection.type);
                
                const portItem = document.createElement('div');
                portItem.className = `port-item`;
                
                if (isConnected) {
                    portItem.classList.add('connected');
                    if (isHub) {
                        portItem.classList.add('hub');
                    } else {
                        // Derive CSS class: "VLAN 30" → "vlan", others use lowercase type
                        const typeClass = isVlanType ? 'vlan' : (connection.type?.toLowerCase() || 'device');
                        portItem.classList.add(typeClass);
                    }
                }
                // Mark DOWN ports with red border
                if (isDown) {
                    portItem.classList.add('down');
                }
                // Also mark VLAN-type UP ports with the vlan class (red)
                if (isVlanType && !isDown) {
                    portItem.classList.add('connected');
                    portItem.classList.add('vlan');
                }
                
                portItem.dataset.port = i;
                
                let portType = 'BOŞ';
                let deviceName = '';
                let rackPort = '';
                let isFiber = i > (sw.ports - 4); // Son 4 port fiber
                
                if (isConnected || isVlanType) {
                    if (isHub) {
                        portType = 'HUB';
                        deviceName = connection.hub_name || 'Hub Port';
                        
                        // Cihaz sayısını göster
                        if (connection.device_count > 0) {
                            deviceName = `Hub (${connection.device_count} cihaz)`;
                        } else if (connection.ip_count > 1 || connection.mac_count > 1) {
                            const deviceCount = Math.max(connection.ip_count || 0, connection.mac_count || 0);
                            deviceName = `Hub (${deviceCount} cihaz)`;
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
                
                // CSS class for port-type badge: "VLAN 30" → 'vlan', others lowercase
                const portTypeCss = isVlanType ? 'vlan' : portType.toLowerCase();
                
portItem.innerHTML = `
    <div class="port-number">${i}</div>
    <div class="port-type ${portTypeCss}">${portType}${isDown ? ' ↓' : ''}</div>
    <div class="port-device">${deviceName}</div>
    ${rackPort ? `<div class="port-rack">${rackPort}</div>` : ''}
    ${isHub ? '<div class="hub-icon">H</div>' : ''}
    ${hasConnection ? '<div class="connection-indicator" title="Bağlantı Detayı"><i class="fas fa-link"></i></div>' : ''}
`;

// ---
// add data-* attributes for tooltip and logic
if (connection) {
    // connection may contain: connection_info_preserved, connection_info, multiple_connections
    const connPreserved = connection.connection_info_preserved || '';
    const connJson = connection.connection_info || connection.multiple_connections || '';

    if (connPreserved) {
        portItem.setAttribute('data-connection', connPreserved);
    } else {
        portItem.removeAttribute('data-connection');
    }

    if (connection.multiple_connections) {
        // multiple connections stored as JSON string
        portItem.setAttribute('data-multiple', connection.multiple_connections);
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
// Panel bilgileri – tooltip ve port detay modalı için
portItem.setAttribute('data-panel-id',     connection && connection.connected_panel_id   ? connection.connected_panel_id   : '');
portItem.setAttribute('data-panel-port',   connection && connection.connected_panel_port ? connection.connected_panel_port : '');
portItem.setAttribute('data-panel-letter', connection && connection.connected_panel_letter ? connection.connected_panel_letter : '');
portItem.setAttribute('data-panel-rack',   connection && connection.connected_panel_rack  ? connection.connected_panel_rack  : '');
portItem.setAttribute('data-switch-id',    sw.id);
portItem.setAttribute('data-snmp-vlan',    connection && connection.snmp_vlan_id ? connection.snmp_vlan_id : '');
portItem.setAttribute('data-vlan',         connection && connection.snmp_vlan_id ? connection.snmp_vlan_id : '');

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

        // Tooltip'leri attach et
        setTimeout(() => {
            attachPortHoverTooltips('#detail-ports-grid .port-item');
        }, 100);
        }

        function hideDetailPanel() {
            const detailPanel = document.getElementById('detail-panel');
            detailPanel.style.display = 'none';
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
            subtitle.textContent = sw ? sw.name + ' — ' + (sw.ip || '') : '';
            content.innerHTML = `<div style="text-align:center;padding:40px;"><i class="fas fa-spinner fa-spin" style="font-size:2rem;color:var(--primary);"></i><div style="margin-top:12px;color:var(--text-light);">SNMP verisi çekiliyor...</div></div>`;
            modal.classList.add('active');

            fetch('snmp_port_detail.php', {
                method: 'POST',
                headers: {'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
                body: JSON.stringify({switch_id: switchId, port: portNum})
            })
            .then(r => r.json())
            .then(d => {
                if (!d.success) {
                    content.innerHTML = `<div style="text-align:center;padding:40px;color:#ef4444;"><i class="fas fa-exclamation-circle fa-2x"></i><div style="margin-top:12px;">${escapeHtml(d.error || 'SNMP verisi alınamadı')}</div></div>`;
                    return;
                }
                const totalPorts = sw ? (parseInt(sw.ports) || 28) : 28;
                const isFiber = portNum > (totalPorts - 4);
                const isUp = d.durum.oper === 'up';
                const statusColor = isUp ? '#10b981' : '#ef4444';

                // Port item from patchPanels
                const portEl = document.querySelector(`#detail-ports-grid .port-item[data-port="${portNum}"]`);
                const panelId     = portEl ? portEl.getAttribute('data-panel-id')     : '';
                const panelPort   = portEl ? portEl.getAttribute('data-panel-port')   : '';
                const panelLetter = portEl ? portEl.getAttribute('data-panel-letter') : '';
                const panelRack   = portEl ? portEl.getAttribute('data-panel-rack')   : '';
                const panelType   = portEl ? (portEl.getAttribute('data-type') === 'FIBER' ? 'fiber' : 'patch') : 'patch';
                const snmpVlan    = portEl ? portEl.getAttribute('data-snmp-vlan') : '';

                let panelHtml = '';
                if (panelId) {
                    panelHtml = `
                    <div class="snmp-section">
                        <h4 class="snmp-section-title"><i class="fas fa-th-large" style="color:#8b5cf6;"></i> Panel Detayı</h4>
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
                    </div>`;
                }

                const vlanHtml = snmpVlan && snmpVlan > 1 ? `<span style="background:rgba(59,130,246,0.2);border:1px solid rgba(59,130,246,0.4);color:#93c5fd;padding:2px 8px;border-radius:12px;font-size:0.75rem;">VLAN ${snmpVlan}</span>` : '';

                let tabsHtml = `<div class="snmp-tabs" id="snmp-detail-tabs">
                    <button class="snmp-tab active" data-tab="temel">Temel</button>
                    <button class="snmp-tab" data-tab="durum">Durum</button>
                    <button class="snmp-tab" data-tab="vlan">VLAN</button>
                    ${!isFiber ? '<button class="snmp-tab" data-tab="poe">PoE</button>' : ''}
                    ${isFiber || d.lldp ? '<button class="snmp-tab" data-tab="lldp">LLDP Komşu</button>' : ''}
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
                        <div class="snmp-row"><span class="snmp-label">Admin</span><span class="snmp-value" style="color:${d.durum.admin==='up'?'#10b981':'#ef4444'}">${d.durum.admin.toUpperCase()}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Oper</span><span class="snmp-value" style="color:${d.durum.oper==='up'?'#10b981':'#ef4444'}">${d.durum.oper.toUpperCase()}</span></div>
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
                        <div class="snmp-row"><span class="snmp-label">Durum</span><span class="snmp-value" style="color:${d.poe.enabled?'#10b981':'#94a3b8'}">${d.poe.enabled ? 'Aktif' : 'Pasif'}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Güç</span><span class="snmp-value">${escapeHtml(d.poe.power_watt)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Sınıf</span><span class="snmp-value">${escapeHtml(d.poe.class)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Öncelik</span><span class="snmp-value">${escapeHtml(d.poe.priority)}</span></div>
                    </div>
                </div>` : '';

                const lldpHtml = `<div class="snmp-tab-content" data-content="lldp" style="display:none;">
                    ${d.lldp ? `<div class="snmp-grid">
                        <div class="snmp-row"><span class="snmp-label">Sistem Adı</span><span class="snmp-value">${escapeHtml(d.lldp.system_name)}</span></div>
                        <div class="snmp-row"><span class="snmp-label">Port ID</span><span class="snmp-value">${escapeHtml(d.lldp.port_id)}</span></div>
                        ${d.lldp.mgmt_ip ? `<div class="snmp-row"><span class="snmp-label">Yönetim IP</span><span class="snmp-value" style="font-family:monospace">${escapeHtml(d.lldp.mgmt_ip)}</span></div>` : ''}
                        ${d.lldp.capabilities ? `<div class="snmp-row"><span class="snmp-label">Yetenekler</span><span class="snmp-value">${escapeHtml(d.lldp.capabilities)}</span></div>` : ''}
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
                    <span style="background:rgba(${isUp?'16,185,129':'239,68,68'},0.2);border:1px solid rgba(${isUp?'16,185,129':'239,68,68'},0.4);color:${statusColor};padding:2px 10px;border-radius:12px;font-size:0.78rem;font-weight:700;">${isUp?'UP':'DOWN'}</span>
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
                content.innerHTML = `<div style="text-align:center;padding:40px;color:#ef4444;"><i class="fas fa-exclamation-circle fa-2x"></i><div style="margin-top:12px;">${escapeHtml(err.message)}</div></div>`;
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
                const response = await fetch(`getPatchPanels.php?rack_id=${rackId}`);
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
                        const response = await fetch(`backup.php?action=create&name=${encodeURIComponent(name)}`);
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
                        const response = await fetch('backup.php?action=list');
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
                                            const response = await fetch(`backup.php?action=restore&file=${encodeURIComponent(file)}`);
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
                        const response = await fetch('backup.php?action=list');
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
            switches.forEach(sw => {
                const connections = portConnections[sw.id] || [];
                connections.forEach(conn => {
                    // Port bilgilerini ara
                    let found = false;
                    
                    // MAC adresi ara
                    if (conn.mac) {
                        // MAC'i temizleyerek ara (noktalama işaretlerini kaldır)
                        const cleanMac = conn.mac.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
                        const cleanQuery = query.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
                        if (cleanMac.includes(cleanQuery)) {
                            found = true;
                        }
                    }
                    
                    // IP adresi ara
                    if (conn.ip && conn.ip.includes(query)) {
                        found = true;
                    }
                    
                    // Cihaz adı ara
                    if (conn.device && conn.device.toLowerCase().includes(query)) {
                        found = true;
                    }
                    
                    // CONNECTION_INFO_PRESERVED BİLGİSİNDE ARA (fiber paneller vs için)
                    if (conn.connection_info_preserved && conn.connection_info_preserved !== '[]' && conn.connection_info_preserved !== 'null') {
                        // Basit string araması - cihaz ismi connection_info_preserved içinde olabilir
                        if (conn.connection_info_preserved.toLowerCase().includes(query)) {
                            found = true;
                        }
                    }
                    
                    // CONNECTION BİLGİLERİNDE ARA
                    if (conn.connection_info && conn.connection_info !== '[]' && conn.connection_info !== 'null') {
                        try {
                            const connectionData = JSON.parse(conn.connection_info);
                            connectionData.forEach(connItem => {
                                if (connItem.device && connItem.device.toLowerCase().includes(query)) {
                                    found = true;
                                }
                                if (connItem.ip && connItem.ip.includes(query)) {
                                    found = true;
                                }
                                if (connItem.mac) {
                                    const cleanConnMac = connItem.mac.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
                                    const cleanQuery = query.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
                                    if (cleanConnMac.includes(cleanQuery)) {
                                        found = true;
                                    }
                                }
                            });
                        } catch (e) {
                            console.error('Connection search error:', e);
                        }
                    }
                    
                    if (found) {
                        results.push({
                            type: 'connection',
                            switch: sw,
                            connection: conn
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
                                                `<i class="fas fa-plug"></i> Port ${result.connection.port} - ${result.connection.device}` :
                                                `<i class="fas fa-server"></i> ${result.data.name}`}
                                        </div>
                                        <div style="font-size: 0.85rem; color: var(--text-light);">
                                            ${result.type === 'switch' ? 
                                                `${result.data.brand} • ${result.data.ports} Port` :
                                                result.type === 'snmp_device' ?
                                                `${result.data.vendor} ${result.data.model} • ${result.data.ip_address}` :
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
                                        ${result.connection.mac ? `<span><i class="fas fa-id-card"></i> ${result.connection.mac}</span>` : ''}
                                    </div>
                                ` : ''}
                                ${result.type === 'snmp_device' ? `
                                    <div style="display: flex; gap: 15px; font-size: 0.85rem; color: var(--text-light); flex-wrap: wrap;">
                                        <span><i class="fas fa-network-wired"></i> ${result.data.ip_address}</span>
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
                    const response = await fetch('updatePort.php', {
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
                const formData = {
                    id: document.getElementById('switch-id').value,
                    name: document.getElementById('switch-name').value,
                    brand: document.getElementById('switch-brand').value,
                    model: document.getElementById('switch-model').value,
                    ports: parseInt(document.getElementById('switch-ports').value),
                    status: document.getElementById('switch-status').value,
                    rackId: parseInt(document.getElementById('switch-rack').value),
                    positionInRack: position,
                    ip: document.getElementById('switch-ip').value
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
        const response = await fetch('saveRack.php', {
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
                    const response = await fetch('savePatchPanel.php', {
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
                        
                        const response = await fetch('savePortWithPanel.php', {
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
            
            backupIndicator.addEventListener('click', openBackupModal);
            
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
                    showToast(`SNMP Cihazı: ${result.data.name} (${result.data.ip_address})`, 'info');
                }
                
                const modal = document.querySelector('.modal-overlay.active');
                if (modal) modal.remove();
            };
            
            // Port Alarms functionality
            let currentAlarmFilter = 'all';
            
            async function loadPortAlarms(filter = 'all') {
                try {
                    const response = await fetch('port_change_api.php?action=get_active_alarms');
                    const data = await response.json();
                    
                    if (!data.success) {
                        throw new Error(data.error || 'Failed to load alarms');
                    }
                    
                    displayAlarms(data.alarms, filter);
                    updateAlarmBadge(data.alarms.length);
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
                            <div class="alarm-message">${alarm.message}</div>
                            ${alarm.old_value && alarm.new_value ? `
                                <div style="margin: 8px 0; padding: 8px; background: rgba(0,0,0,0.2); border-radius: 5px;">
                                    <span style="color: var(--danger);">${alarm.old_value}</span>
                                    <i class="fas fa-arrow-right" style="margin: 0 8px;"></i>
                                    <span style="color: var(--success);">${alarm.new_value}</span>
                                </div>
                            ` : ''}
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
                                    ${(alarm.alarm_type === 'mac_moved' || alarm.alarm_type === 'mac_added') && alarm.new_value ? `
                                        <button class="btn btn-sm" style="background: #27ae60; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: bold;" onclick="event.stopPropagation(); saveMacAndCloseAlarm(${alarm.id}, '${alarm.new_value}')">
                                            <i class="fas fa-save"></i> MAC Kaydet ve Kapat (${alarm.new_value.replace(/</g,'&lt;').replace(/>/g,'&gt;')})
                                        </button>
                                    ` : ''}
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
                    
                    const response = await fetch('port_change_api.php', {
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
                    const response = await fetch(`port_change_api.php?action=acknowledge_alarm&alarm_id=${alarmId}`);
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
                    const response = await fetch(`port_change_api.php?action=silence_alarm&alarm_id=${alarmId}&duration=${duration}`);
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

                    const response = await fetch('port_change_api.php', { method: 'POST', body: formData });
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
                    const response = await fetch(`port_change_api.php?action=get_alarm_details&alarm_id=${alarmId}`);
                    const data = await response.json();
                    
                    if (data.success && data.alarm) {
                        const alarm = data.alarm;
                        const details = `
Alarm Detayları:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Cihaz: ${alarm.device_name} (${alarm.device_ip})
Port: ${alarm.port_number || 'N/A'}
Tip: ${alarm.alarm_type}
Seviye: ${alarm.severity}

Mesaj: ${alarm.message}

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
                    fetch('port_change_api.php?action=get_active_alarms')
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                updateAlarmBadge(data.alarms.length);
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
                    const response = await fetch('saveFiberPanel.php', {
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
                    const response = await fetch('updatePort.php', {
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
            }
        }

        document.addEventListener('DOMContentLoaded', init);
        
        // Handle URL parameters after init
        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(handleURLParameters, 1000); // Wait for data to load
        });
        
        // Listen for messages from iframe (e.g., port_alarms.php)
        window.addEventListener('message', function(event) {
            // Security check - you may want to add origin validation
            if (event.data && event.data.action === 'navigateToPort') {
                const switchName = event.data.switchName;
                const portNumber = event.data.portNumber;
                
                console.log('Received navigateToPort message:', switchName, portNumber);
                
                // Navigate to switches page first
                updatePageContent('switches');
                
                // Wait for switches page to load, then find and open the switch
                setTimeout(() => {
                    const switchToOpen = switches.find(s => s.name === switchName);
                    if (switchToOpen) {
                        console.log('Opening switch:', switchToOpen);
                        showSwitchDetail(switchToOpen);
                        
                        // Highlight the specific port after a small delay
                        setTimeout(() => {
                            const portElement = document.querySelector(`#detail-ports-grid .port-item[data-port="${portNumber}"]`);
                            if (portElement) {
                                portElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                portElement.style.animation = 'pulse 2s ease-in-out 3';
                            }
                        }, 500);
                    } else {
                        showToast('Switch bulunamadı: ' + switchName, 'error');
                    }
                }, 1000);
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
                const response = await fetch(`snmp_realtime_api.php?action=check_new_alarms&last_check=${encodeURIComponent(lastAlarmCheck)}`);
                
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
                const response = await fetch('snmp_realtime_api.php?action=get_alarm_count');
                
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
                const body = `${alarm.device_name} - ${alarm.message}`;
                
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
                            ${alarm.message}
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