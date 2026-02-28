-- MAC Device Registry Table
-- Bu tablo Excel'den yüklenen veya manuel girilen cihaz bilgilerini saklar
-- Domain server'dan bulunamayanlar için yedek kaynak

CREATE TABLE IF NOT EXISTS mac_device_registry (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    device_name VARCHAR(255),
    user_name VARCHAR(255),
    location VARCHAR(255),
    department VARCHAR(100),
    notes TEXT,
    source ENUM('domain', 'excel', 'manual') DEFAULT 'manual',
    last_seen TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by VARCHAR(100),
    updated_by VARCHAR(100),
    INDEX idx_mac (mac_address),
    INDEX idx_ip (ip_address),
    INDEX idx_device_name (device_name),
    INDEX idx_source (source),
    INDEX idx_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Import history table (optional)
CREATE TABLE IF NOT EXISTS mac_device_import_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255),
    total_rows INT,
    success_count INT,
    error_count INT,
    imported_by VARCHAR(100),
    import_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    errors TEXT,
    INDEX idx_date (import_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
