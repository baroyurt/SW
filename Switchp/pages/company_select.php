<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();

// Sadece admin bu sayfaya erişebilir; personel doğrudan index'e yönlendirilir
if (!$auth->isAdmin()) {
    header('Location: ../index.php');
    exit;
}

$currentUser = $_SESSION;
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistem Seçimi - Switch Yönetim Sistemi</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .select-container {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            padding: 50px 40px 40px;
            width: 100%;
            max-width: 600px;
            text-align: center;
        }

        .select-header {
            margin-bottom: 40px;
        }

        .select-header i {
            font-size: 60px;
            color: #3b82f6;
            margin-bottom: 20px;
        }

        .select-header h1 {
            color: #e2e8f0;
            font-size: 26px;
            margin-bottom: 10px;
        }

        .select-header p {
            color: #94a3b8;
            font-size: 14px;
        }

        .welcome-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            color: #93c5fd;
            padding: 8px 18px;
            border-radius: 50px;
            font-size: 13px;
            margin-bottom: 40px;
        }

        .companies-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 35px;
        }

        .company-card {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 15px;
            padding: 35px 20px;
            border-radius: 16px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s ease;
            border: 2px solid transparent;
            position: relative;
            overflow: hidden;
        }

        /* PRESTİGE - aktif, mavi */
        .company-card.prestige {
            background: linear-gradient(135deg, rgba(37, 99, 235, 0.15) 0%, rgba(59, 130, 246, 0.1) 100%);
            border-color: rgba(59, 130, 246, 0.4);
        }

        .company-card.prestige:hover {
            background: linear-gradient(135deg, rgba(37, 99, 235, 0.3) 0%, rgba(59, 130, 246, 0.2) 100%);
            border-color: #3b82f6;
            transform: translateY(-4px);
            box-shadow: 0 15px 35px rgba(59, 130, 246, 0.25);
        }

        /* GİRNE - bakımda, turuncu */
        .company-card.girne {
            background: linear-gradient(135deg, rgba(217, 119, 6, 0.15) 0%, rgba(245, 158, 11, 0.1) 100%);
            border-color: rgba(245, 158, 11, 0.4);
        }

        .company-card.girne:hover {
            background: linear-gradient(135deg, rgba(217, 119, 6, 0.3) 0%, rgba(245, 158, 11, 0.2) 100%);
            border-color: #f59e0b;
            transform: translateY(-4px);
            box-shadow: 0 15px 35px rgba(245, 158, 11, 0.2);
        }

        .company-card .company-icon {
            font-size: 42px;
        }

        .company-card.prestige .company-icon { color: #60a5fa; }
        .company-card.girne    .company-icon { color: #fbbf24; }

        .company-card .company-name {
            font-size: 22px;
            font-weight: 700;
            letter-spacing: 1px;
        }

        .company-card.prestige .company-name { color: #e2e8f0; }
        .company-card.girne    .company-name { color: #fde68a; }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 5px 12px;
            border-radius: 50px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .status-active {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #6ee7b7;
        }

        .status-maintenance {
            background: rgba(245, 158, 11, 0.15);
            border: 1px solid rgba(245, 158, 11, 0.3);
            color: #fcd34d;
        }

        .logout-link {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: #64748b;
            font-size: 13px;
            text-decoration: none;
            transition: color 0.2s;
            margin-top: 5px;
        }

        .logout-link:hover {
            color: #94a3b8;
        }

        @media (max-width: 480px) {
            .companies-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="select-container">
        <div class="select-header">
            <img src="../logo.png" alt="CHAMADA" style="width:60px;height:60px;object-fit:contain;margin-bottom:8px;">
            <h1>Switch Yönetim Sistemi</h1>
            <p>Yönetmek istediğiniz sistemi seçin</p>
        </div>

        <div class="welcome-badge">
            <i class="fas fa-user-shield"></i>
            <span>Hoşgeldiniz, <?php echo htmlspecialchars($currentUser['full_name'] ?? $currentUser['username']); ?></span>
        </div>

        <div class="companies-grid">
            <!-- PRESTİGE — aktif sistem -->
            <a href="../index.php" class="company-card prestige">
                <i class="fas fa-building company-icon"></i>
                <span class="company-name">PRESTİGE</span>
                <span class="status-badge status-active">
                    <i class="fas fa-circle" style="font-size:8px;"></i>
                    AKTİF
                </span>
            </a>

            <!-- GİRNE — bakımda -->
            <a href="maintenance.php" class="company-card girne">
                <i class="fas fa-city company-icon"></i>
                <span class="company-name">GİRNE</span>
                <span class="status-badge status-maintenance">
                    <i class="fas fa-tools" style="font-size:9px;"></i>
                    BAKIMDA
                </span>
            </a>
        </div>

        <a href="../logout.php" class="logout-link">
            <i class="fas fa-sign-out-alt"></i>
            Çıkış Yap
        </a>
    </div>
</body>
</html>
