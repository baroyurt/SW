<?php
/**
 * Maintenance page – shown during scheduled or manual maintenance windows.
 * If db.php is available, reads the currently active window from
 * the maintenance_windows table and shows its title / end time.
 */

$activeWindow = null;
if (file_exists(__DIR__ . '/../db.php')) {
    include_once __DIR__ . '/../db.php';
    if (isset($conn) && $conn instanceof mysqli) {
        // Ensure table exists (lightweight – only runs CREATE TABLE IF NOT EXISTS)
        $conn->query("CREATE TABLE IF NOT EXISTS maintenance_windows (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            title        VARCHAR(255)  NOT NULL,
            description  TEXT          DEFAULT NULL,
            start_time   DATETIME      NOT NULL,
            end_time     DATETIME      NOT NULL,
            created_by   VARCHAR(100)  DEFAULT NULL,
            is_active    TINYINT(1)    NOT NULL DEFAULT 1,
            notify_users TINYINT(1)    NOT NULL DEFAULT 0,
            created_at   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
            updated_at   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_mw_times (start_time, end_time),
            INDEX idx_mw_active (is_active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $now  = date('Y-m-d H:i:s');
        $stmt = $conn->prepare(
            "SELECT * FROM maintenance_windows
             WHERE is_active = 1 AND start_time <= ? AND end_time >= ?
             ORDER BY start_time DESC LIMIT 1"
        );
        if ($stmt) {
            $stmt->bind_param('ss', $now, $now);
            $stmt->execute();
            $activeWindow = $stmt->get_result()->fetch_assoc();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bakımda - GİRNE Switch Yönetim Sistemi</title>
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

        .maintenance-container {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            padding: 60px 40px;
            width: 100%;
            max-width: 500px;
            text-align: center;
        }

        .maintenance-icon {
            font-size: 80px;
            color: #f59e0b;
            margin-bottom: 30px;
            display: block;
            animation: pulse 2.5s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50%       { opacity: 0.7; transform: scale(0.95); }
        }

        .location-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
            color: #fcd34d;
            padding: 6px 18px;
            border-radius: 50px;
            font-size: 13px;
            font-weight: 600;
            letter-spacing: 1px;
            margin-bottom: 25px;
        }

        h1 {
            color: #e2e8f0;
            font-size: 30px;
            margin-bottom: 15px;
        }

        .subtitle {
            color: #94a3b8;
            font-size: 15px;
            line-height: 1.7;
            margin-bottom: 40px;
        }

        .info-box {
            background: rgba(245, 158, 11, 0.08);
            border: 1px solid rgba(245, 158, 11, 0.2);
            border-radius: 12px;
            padding: 20px 25px;
            margin-bottom: 35px;
        }

        .info-box p {
            color: #fde68a;
            font-size: 13px;
            line-height: 1.7;
        }

        .info-box i {
            color: #f59e0b;
            margin-right: 6px;
        }

        .back-link {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.15), rgba(37, 99, 235, 0.1));
            border: 1px solid rgba(59, 130, 246, 0.3);
            color: #93c5fd;
            padding: 12px 28px;
            border-radius: 10px;
            text-decoration: none;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .back-link:hover {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.3), rgba(37, 99, 235, 0.2));
            border-color: #3b82f6;
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(59, 130, 246, 0.2);
        }

        .footer-note {
            margin-top: 30px;
            color: #475569;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="maintenance-container">
        <i class="fas fa-tools maintenance-icon"></i>

        <div class="location-badge">
            <i class="fas fa-map-marker-alt"></i>
            <?php echo $activeWindow ? htmlspecialchars($activeWindow['created_by'] ?? 'SİSTEM') : 'SİSTEM'; ?>
        </div>

        <h1>
            <?php echo $activeWindow
                ? htmlspecialchars($activeWindow['title'])
                : 'Sistem Bakımda'; ?>
        </h1>
        <p class="subtitle">
            <?php echo $activeWindow
                ? htmlspecialchars($activeWindow['description'] ?? 'Switch Yönetim Sistemi şu anda bakım modundadır.')
                : 'Switch Yönetim Sistemi şu anda kurulum ve yapılandırma aşamasındadır.'; ?>
        </p>

        <?php if ($activeWindow): ?>
        <div class="info-box">
            <p>
                <i class="fas fa-clock"></i>
                Bakım Başlangıcı: <strong><?php echo date('d.m.Y H:i', strtotime($activeWindow['start_time'])); ?></strong>
            </p>
            <p style="margin-top:8px;">
                <i class="fas fa-hourglass-end"></i>
                Tahmini Bitiş: <strong><?php echo date('d.m.Y H:i', strtotime($activeWindow['end_time'])); ?></strong>
            </p>
        </div>
        <?php else: ?>
        <div class="info-box">
            <p>
                <i class="fas fa-info-circle"></i>
                Bakım tamamlandığında sistem aktif hale getirilecektir.
                Yönetici erişimi için lütfen tekrar ziyaret edin.
            </p>
        </div>
        <?php endif; ?>

        <a href="company_select.php" class="back-link">
            <i class="fas fa-arrow-left"></i>
            Sistem Seçimine Dön
        </a>

        <p class="footer-note">Switch Yönetim Sistemi &copy; <?php echo date('Y'); ?></p>
    </div>
</body>
</html>
