#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP Worker - Main entry point.
Runs the polling engine continuously.
"""

# Ultra-defensive startup: Catch ANY error and report it
import sys

# Check Python version first
if sys.version_info < (3, 7):
    print("\n" + "="*60)
    print("HATA: Python 3.7 veya uzeri gereklidir!")
    print("="*60)
    print(f"\nMevcut Python versiyonu: {sys.version}")
    print("\nLutfen Python 3.7+ yukleyin:")
    print("  https://www.python.org/downloads/")
    print("\n" + "="*60 + "\n")
    sys.exit(1)

# Try to import standard library modules
try:
    import signal
    import time
    import logging
    import threading
    from pathlib import Path
except Exception as e:
    print("\n" + "="*60)
    print("KRITIK HATA: Standart kutuphaneler yuklenemedi!")
    print("="*60)
    print(f"\nHata: {e}")
    print(f"Hata tipi: {type(e).__name__}")
    print("\nPython kurulumunuz bozuk olabilir.")
    print("Python'u yeniden yukleyin:")
    print("  https://www.python.org/downloads/")
    print("\n" + "="*60 + "\n")
    sys.exit(1)

# Pre-flight check: Verify critical packages are available
def check_dependencies():
    """Check if all required packages are installed."""
    missing = []
    
    try:
        import yaml
    except ImportError:
        missing.append("pyyaml")
    
    try:
        import sqlalchemy
    except ImportError:
        missing.append("sqlalchemy")
    
    try:
        import pyodbc
    except ImportError:
        missing.append("pyodbc")
    
    try:
        import pysnmp
    except ImportError:
        missing.append("pysnmp")
    
    if missing:
        print("\n" + "="*60)
        print("HATA: Gerekli Python paketleri eksik!")
        print("="*60)
        print("\nEksik paketler:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\nPaketleri kurmak icin:")
        print("  1. Virtual environment'i aktif edin:")
        print("     venv\\Scripts\\activate  (Windows)")
        print("     source venv/bin/activate  (Linux/Mac)")
        print("\n  2. Paketleri kurun:")
        print("     pip install -r requirements.txt")
        print("\n  Veya tek tek:")
        print(f"     pip install {' '.join(missing)}")
        print("\n" + "="*60 + "\n")
        sys.exit(1)

# Run dependency check before imports
check_dependencies()

# Import from local modules with enhanced error handling
# Import each module individually to identify which one fails

def import_with_diagnostics():
    """Import modules with detailed diagnostics for each module."""
    modules_to_import = []
    
    try:
        print("  [1/7] Importing config.config_loader...", end=" ", flush=True)
        from config.config_loader import Config
        modules_to_import.append(("Config", Config))
        print("OK")
    except Exception as e:
        print(f"FAILED")
        print("\n" + "="*60)
        print("HATA: Config modulü import edilemedi!")
        print("="*60)
        print(f"\nHata: {e}")
        print(f"Hata tipi: {type(e).__name__}")
        print("\nNeden:")
        print("  - config/config_loader.py dosyasi bulunamadi")
        print("  - config/config.yml hatali veya eksik")
        print("  - pyyaml paketi eksik")
        print("\nCozum:")
        print("  pip install pyyaml")
        print("  config/config.yml dosyasini kontrol edin")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    try:
        print("  [2/7] Importing core.database_manager...", end=" ", flush=True)
        from core.database_manager import DatabaseManager
        modules_to_import.append(("DatabaseManager", DatabaseManager))
        print("OK")
    except Exception as e:
        print(f"FAILED")
        print("\n" + "="*60)
        print("HATA: DatabaseManager modulü import edilemedi!")
        print("="*60)
        print(f"\nHata: {e}")
        print(f"Hata tipi: {type(e).__name__}")
        print("\nOlasilıklar:")
        print("  - pytz paketi eksik (timezone desteği için gerekli)")
        print("  - sqlalchemy paketi eksik")
        print("  - models/database.py dosyasi eksik")
        print("  - pyodbc paketi eksik")
        print("\nHizli Cozum:")
        print("  pip install pytz")
        print("\nYa da tum bagimliliklar:")
        print("  pip install -r requirements.txt")
        print("\nYa da:")
        print("  install_dependencies.bat dosyasini calistirin")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    try:
        print("  [3/7] Importing core.alarm_manager...", end=" ", flush=True)
        from core.alarm_manager import AlarmManager
        modules_to_import.append(("AlarmManager", AlarmManager))
        print("OK")
    except Exception as e:
        print(f"FAILED")
        print("\n" + "="*60)
        print("HATA: AlarmManager modulü import edilemedi!")
        print("="*60)
        print(f"\nHata: {e}")
        print("\nCozum:")
        print("  core/alarm_manager.py dosyasini kontrol edin")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    try:
        print("  [4/7] Importing core.polling_engine...", end=" ", flush=True)
        from core.polling_engine import PollingEngine
        modules_to_import.append(("PollingEngine", PollingEngine))
        print("OK")
    except Exception as e:
        print(f"FAILED")
        print("\n" + "="*60)
        print("HATA: PollingEngine modulü import edilemedi!")
        print("="*60)
        print(f"\nHata: {e}")
        print("\nCozum:")
        print("  core/polling_engine.py dosyasini kontrol edin")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    try:
        print("  [5/7] Importing services.telegram_service...", end=" ", flush=True)
        from services.telegram_service import TelegramNotificationService
        modules_to_import.append(("TelegramNotificationService", TelegramNotificationService))
        print("OK")
    except Exception as e:
        print(f"FAILED")
        print("\n" + "="*60)
        print("HATA: TelegramNotificationService modulü import edilemedi!")
        print("="*60)
        print(f"\nHata: {e}")
        print("\nCozum:")
        print("  services/telegram_service.py dosyasini kontrol edin")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    try:
        print("  [6/8] Importing services.email_service...", end=" ", flush=True)
        from services.email_service import EmailNotificationService
        modules_to_import.append(("EmailNotificationService", EmailNotificationService))
        print("OK")
    except Exception as e:
        print(f"FAILED")
        print("\n" + "="*60)
        print("HATA: EmailNotificationService modulü import edilemedi!")
        print("="*60)
        print(f"\nHata: {e}")
        print("\nCozum:")
        print("  services/email_service.py dosyasini kontrol edin")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    try:
        print("  [7/8] Importing services.autosync_service...", end=" ", flush=True)
        from services.autosync_service import AutoSyncService
        modules_to_import.append(("AutoSyncService", AutoSyncService))
        print("OK")
    except Exception as e:
        print(f"FAILED")
        print("\n" + "="*60)
        print("HATA: AutoSyncService modulü import edilemedi!")
        print("="*60)
        print(f"\nHata: {e}")
        print("\nCozum:")
        print("  services/autosync_service.py dosyasini kontrol edin")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    try:
        print("  [8/8] Importing utils.logger...", end=" ", flush=True)
        from utils.logger import setup_logging, stop_listener
        modules_to_import.append(("setup_logging", setup_logging))
        modules_to_import.append(("stop_listener", stop_listener))
        print("OK")
    except Exception as e:
        print(f"FAILED")
        print("\n" + "="*60)
        print("HATA: setup_logging modulü import edilemedi!")
        print("="*60)
        print(f"\nHata: {e}")
        print("\nCozum:")
        print("  utils/logger.py dosyasini kontrol edin")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # WeeklyReportService is optional – worker starts even if it fails
    try:
        print("  [opt] Importing services.weekly_report_service...", end=" ", flush=True)
        from services.weekly_report_service import WeeklyReportService
        modules_to_import.append(("WeeklyReportService", WeeklyReportService))
        print("OK")
    except Exception as e:
        print(f"SKIPPED ({e})")
        modules_to_import.append(("WeeklyReportService", None))
    
    print("\n  All modules imported successfully!\n")
    
    # Return the imported modules as a dictionary
    return {name: module for name, module in modules_to_import}

# Perform imports with diagnostics
print("\nImporting worker modules...")
imported = import_with_diagnostics()

# Assign to variables for use in the rest of the code
Config = imported["Config"]
DatabaseManager = imported["DatabaseManager"]
AlarmManager = imported["AlarmManager"]
PollingEngine = imported["PollingEngine"]
TelegramNotificationService = imported["TelegramNotificationService"]
EmailNotificationService = imported["EmailNotificationService"]
AutoSyncService = imported["AutoSyncService"]
setup_logging = imported["setup_logging"]
stop_listener = imported["stop_listener"]
WeeklyReportService = imported.get("WeeklyReportService")


class SNMPWorker:
    """Main SNMP Worker daemon."""
    
    def __init__(self, config_file: str = None):
        """
        Initialize SNMP Worker.
        
        Args:
            config_file: Path to configuration file
        """
        self.running = False
        self._stop_event = threading.Event()
        self.config = None
        self.db_manager = None
        self.alarm_manager = None
        self.polling_engine = None
        self.autosync_service = None
        self.logger = None
        
        # Load configuration
        try:
            self.config = Config(config_file)
        except Exception as e:
            raise RuntimeError(f"Error loading configuration: {e}") from e
        
        # Set timezone from config (using Config object attribute access)
        import os
        try:
            # Config object uses attribute access, not dictionary methods
            timezone_str = getattr(self.config.system, 'timezone', 'UTC')
        except (AttributeError, KeyError):
            # If system section doesn't exist, fall back to UTC
            timezone_str = 'UTC'
        
        if timezone_str and timezone_str != 'UTC':
            os.environ['TZ'] = timezone_str
            try:
                import time
                time.tzset()
                print(f"Timezone set to: {timezone_str}")
            except AttributeError:
                # tzset() not available on Windows
                print(f"Timezone configured: {timezone_str} (Windows - manual timezone)")
        
        # Setup logging
        self.logger = setup_logging(
            log_level=self.config.logging.level,
            log_format=self.config.logging.format,
            log_file=self.config.logging.file,
            max_bytes=self.config.logging.max_bytes,
            backup_count=self.config.logging.backup_count,
            console=self.config.logging.console
        )
        
        self.logger.info("=" * 60)
        self.logger.info("SNMP Worker Starting")
        self.logger.info("=" * 60)
        
        # Initialize components
        self._initialize_components()
        
        # Setup signal handlers — only valid from the main Python thread.
        # When running as a Windows Service the SCM calls SvcDoRun from a
        # non-main thread, so signal.signal() would raise ValueError.
        # We skip registration silently in that case; the service uses
        # SNMPWorker.stop() directly via SvcStop() instead.
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (ValueError, OSError):
            pass  # Not on main thread or platform does not support it
    
    def _ensure_alarm_severity_config(self):
        """
        Create the alarm_severity_config table if it does not exist and seed
        it with the default alarm types.  Uses UPDATE-then-INSERT so existing
        admin customisations are never overwritten.
        """
        from sqlalchemy import text as _text

        DDL = """
        IF OBJECT_ID('dbo.alarm_severity_config', 'U') IS NULL BEGIN
            CREATE TABLE alarm_severity_config (
                id               INT IDENTITY(1,1) PRIMARY KEY,
                alarm_type       VARCHAR(50)  NOT NULL,
                severity         VARCHAR(50)  NOT NULL DEFAULT 'MEDIUM',
                telegram_enabled BIT          DEFAULT 1,
                email_enabled    BIT          DEFAULT 1,
                description      VARCHAR(255),
                created_at       DATETIME     DEFAULT GETDATE(),
                updated_at       DATETIME     DEFAULT GETDATE(),
                CONSTRAINT uq_alarm_type_asc UNIQUE (alarm_type)
            )
        END
        """

        # Default rows: (alarm_type, severity, telegram, email, description)
        DEFAULTS = [
            ("device_unreachable",  "CRITICAL", 1, 1, "Cihaz erişilemez durumda"),
            ("multiple_ports_down", "CRITICAL", 1, 1, "Birden fazla port çalışmıyor"),
            ("core_link_down",      "CRITICAL", 1, 1, "Core uplink bağlantısı kesildi"),
            ("fan_failure",         "CRITICAL", 1, 1, "Fan arızası"),
            ("mac_moved",           "HIGH",     1, 1, "MAC adresi taşındı"),
            ("port_down",           "HIGH",     1, 1, "Port düştü"),
            ("high_temperature",    "HIGH",     1, 1, "Yüksek sıcaklık (≥70°C)"),
            ("high_cpu",            "HIGH",     1, 1, "Yüksek işlemci kullanımı (≥%30)"),
            ("vlan_changed",        "MEDIUM",   0, 1, "VLAN değişti"),
            ("port_up",             "MEDIUM",   0, 1, "Port aktif oldu"),
            ("description_changed", "LOW",      0, 0, "Port açıklaması değişti"),
            ("mac_added",           "MEDIUM",   0, 1, "Yeni MAC adresi tespit edildi"),
            ("snmp_error",          "HIGH",     1, 1, "SNMP hatası"),
        ]

        try:
            engine = self.db_manager.engine
            with engine.begin() as conn:
                conn.execute(_text(DDL))
                for alarm_type, severity, tg, em, desc in DEFAULTS:
                    conn.execute(
                        _text(
                            "IF NOT EXISTS (SELECT 1 FROM alarm_severity_config WHERE alarm_type = :t) "
                            "INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) "
                            "VALUES (:t, :s, :tg, :em, :desc)"
                        ),
                        {"t": alarm_type, "s": severity, "tg": tg, "em": em, "desc": desc},
                    )
            self.logger.info("alarm_severity_config: table ready with default rows")
        except Exception as exc:
            # Non-fatal: fall back to hardcoded defaults in alarm_manager.py
            self.logger.warning(f"Could not seed alarm_severity_config: {exc}")

    def _ensure_alarm_user_email_config(self):
        """
        Create the alarm_user_email_config table if it does not exist.
        This table stores per-user per-alarm-type email notification preferences
        and is managed via the PHP admin UI (Alarm Seviyeleri → Email Alıcıları).
        Creating it here ensures the Python worker can query it even before the
        admin UI has been used for the first time.
        """
        from sqlalchemy import text as _text

        DDL = """
        IF OBJECT_ID('dbo.alarm_user_email_config', 'U') IS NULL BEGIN
            CREATE TABLE alarm_user_email_config (
                alarm_type    VARCHAR(100) NOT NULL,
                user_id       INT          NOT NULL,
                email_enabled BIT          NOT NULL DEFAULT 1,
                CONSTRAINT PK_alarm_user_email_config PRIMARY KEY (alarm_type, user_id)
            )
        END
        """

        try:
            engine = self.db_manager.engine
            with engine.begin() as conn:
                conn.execute(_text(DDL))
            self.logger.info("alarm_user_email_config: table ready")
        except Exception as exc:
            self.logger.warning(f"Could not create alarm_user_email_config: {exc}")

    def _ensure_maintenance_windows_table(self):
        """
        Create the maintenance_windows table if it does not exist.
        The Python alarm_manager queries this table to suppress alarms during
        scheduled maintenance periods (suppress_alarms = 1).
        """
        from sqlalchemy import text as _text

        DDL = """
        IF OBJECT_ID('dbo.maintenance_windows', 'U') IS NULL BEGIN
            CREATE TABLE maintenance_windows (
                id              INT IDENTITY(1,1) PRIMARY KEY,
                device_id       INT          DEFAULT NULL,
                device_name     VARCHAR(100) DEFAULT NULL,
                title           VARCHAR(255) NOT NULL,
                start_time      DATETIME     NOT NULL,
                end_time        DATETIME     NOT NULL,
                recurring       BIT          DEFAULT 0,
                recur_days      VARCHAR(20)  DEFAULT NULL,
                recur_start     TIME         DEFAULT NULL,
                recur_end       TIME         DEFAULT NULL,
                suppress_alarms BIT          DEFAULT 1,
                created_by      VARCHAR(100) DEFAULT NULL,
                created_at      DATETIME     DEFAULT GETDATE(),
                updated_at      DATETIME     DEFAULT GETDATE()
            );
            CREATE INDEX idx_mw_device ON maintenance_windows(device_id);
            CREATE INDEX idx_mw_times  ON maintenance_windows(start_time, end_time);
        END
        """

        try:
            engine = self.db_manager.engine
            with engine.begin() as conn:
                conn.execute(_text(DDL))
            self.logger.info("maintenance_windows: table ready")
        except Exception as exc:
            self.logger.warning(f"Could not create maintenance_windows: {exc}")

    def _initialize_components(self):
        """Initialize all worker components."""
        try:
            # Database manager
            self.logger.info("Initializing database manager...")
            self.db_manager = DatabaseManager(self.config)
            
            # Test database connection
            with self.db_manager.session_scope() as session:
                pass
            self.logger.info("Database connection successful")

            # Ensure alarm_severity_config table exists and has default rows.
            # The table is not managed by SQLAlchemy ORM (it lives in a plain SQL
            # migration file), so we create and seed it here on every startup.
            # The INSERT statements are no-ops when the row already exists.
            self._ensure_alarm_severity_config()
            self._ensure_alarm_user_email_config()
            self._ensure_maintenance_windows_table()
            
            # Notification services
            telegram_service = None
            if self.config.telegram.enabled:
                self.logger.info("Initializing Telegram notification service...")
                telegram_service = TelegramNotificationService(
                    bot_token=self.config.telegram.bot_token,
                    chat_id=self.config.telegram.chat_id,
                    enabled=self.config.telegram.enabled
                )
            
            email_service = None
            if self.config.email.enabled:
                self.logger.info("Initializing email notification service...")
                email_service = EmailNotificationService(
                    smtp_host=self.config.email.smtp_host,
                    smtp_port=self.config.email.smtp_port,
                    smtp_user=self.config.email.smtp_user,
                    smtp_password=self.config.email.smtp_password,
                    from_address=self.config.email.from_address,
                    to_addresses=self.config.email.to_addresses,
                    enabled=self.config.email.enabled,
                    smtp_ssl_verify=getattr(self.config.email, 'smtp_ssl_verify', False)
                )
            
            # Alarm manager
            self.logger.info("Initializing alarm manager...")
            self.alarm_manager = AlarmManager(
                self.config,
                self.db_manager,
                telegram_service,
                email_service
            )
            
            # Polling engine
            self.logger.info("Initializing polling engine...")
            self.polling_engine = PollingEngine(
                self.config,
                self.db_manager,
                self.alarm_manager
            )
            
            # Auto sync service
            self.logger.info("Initializing auto sync service...")
            self.autosync_service = AutoSyncService(self.db_manager)

            # Weekly report service
            self.weekly_report_service = None
            if WeeklyReportService is not None and email_service and email_service.enabled:
                self.logger.info("Initializing weekly report service…")
                self.weekly_report_service = WeeklyReportService(
                    db_manager=self.db_manager,
                    email_service=email_service,
                    weekday=getattr(getattr(self.config, 'reports', None), 'weekly_weekday', 0),
                    hour=getattr(getattr(self.config, 'reports', None), 'weekly_hour', 8),
                )
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            raise
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals (SIGINT / SIGTERM)."""
        signal_names = {
            signal.SIGINT: "SIGINT",
            signal.SIGTERM: "SIGTERM"
        }
        signal_name = signal_names.get(signum, str(signum))
        self.logger.info(f"Received {signal_name}, shutting down gracefully...")
        self.stop()

    def stop(self):
        """
        Thread-safe stop: signal the run() loop to exit on the next iteration
        and wake any inter-cycle sleep immediately.
        Called by signal handlers (main-thread) and by the Windows Service's
        SvcStop() (SCM thread).
        """
        self.running = False
        self._stop_event.set()

    def run(self):
        """Run the main worker loop."""
        self.running = True
        
        self.logger.info("=" * 60)
        self.logger.info("SNMP Worker Started")
        self.logger.info(f"Polling interval: {self.config.polling.interval} seconds")
        self.logger.info(f"Enabled devices: {len(self.config.devices)}")
        self.logger.info("=" * 60)
        
        cycle_count = 0
        
        try:
            while self.running:
                cycle_count += 1
                cycle_start = time.time()
                self.logger.debug(f"Döngü #{cycle_count} başlıyor")
                
                try:
                    # ── FAZ 1: SNMP veri toplama ─────────────────────────────
                    # Tüm switch'ler aynı anda paralel sorgulanır (saf ağ I/O).
                    # CPU yükü düşüktür; pysnmp thread'leri ağı beklerken
                    # işlemci boşta kalır.
                    _t_faz1 = time.time()
                    paired = self.polling_engine.collect_all()
                    _faz1_sec = time.time() - _t_faz1

                    # ── FAZ 2: DB yazma + alarm işleme ───────────────────────
                    # Ham sonuçlar paralel olarak veritabanına kaydedilir.
                    _t_faz2 = time.time()
                    results = self.polling_engine.process_results(paired)
                    _faz2_sec = time.time() - _t_faz2

                    # Özet
                    successful = sum(1 for r in results if r['success'])
                    failed = len(results) - successful
                    cycle_elapsed = time.time() - cycle_start
                    self.logger.debug(
                        f"Döngü #{cycle_count} tamamlandı: "
                        f"{successful} başarılı, {failed} başarısız "
                        f"(toplam={cycle_elapsed:.1f}s | "
                        f"faz1={_faz1_sec:.1f}s | faz2={_faz2_sec:.1f}s)"
                    )
                    
                    # Auto sync to main switches table – run every 3rd cycle to
                    # reduce DB load (autosync processes 840+ ports per call on
                    # a 30-switch setup; running it every poll cycle is wasteful).
                    if successful > 0 and cycle_count % 3 == 1:
                        try:
                            with self.db_manager.session_scope() as session:
                                sync_result = self.autosync_service.sync_all_devices(session)
                                if sync_result['success'] and sync_result['synced_count'] > 0:
                                    self.logger.debug(
                                        f"Auto sync: {sync_result['synced_count']} cihaz senkronize edildi"
                                    )
                        except Exception as e:
                            self.logger.error(f"Auto sync hatası: {e}", exc_info=True)
                    
                    # Cleanup old notification timestamps periodically
                    if cycle_count % 10 == 0:
                        self.alarm_manager.cleanup_old_notifications()

                    # Weekly report check (runs on every cycle; service handles
                    # the weekday/hour schedule internally)
                    if self.weekly_report_service is not None:
                        try:
                            self.weekly_report_service.check_and_send()
                        except Exception as e:
                            self.logger.error(f"Weekly report check hatası: {e}", exc_info=True)

                    # Cleanup old polling data and deduplicate port_status_data
                    # every ~25 minutes (50 cycles × 30s).  Removes legacy rows
                    # accumulated before the UPSERT transition.
                    # Also purge old port_snapshot rows (default 30-day retention)
                    # to prevent unbounded table growth.
                    if cycle_count % 50 == 0:
                        try:
                            with self.db_manager.session_scope() as session:
                                self.db_manager.cleanup_old_data(
                                    session,
                                    days=self.config.polling.polling_data_retention_days,
                                )
                                if self.polling_engine and self.polling_engine.change_detector:
                                    deleted = self.polling_engine.change_detector.cleanup_old_snapshots(
                                        session,
                                        days=self.config.polling.snapshot_retention_days,
                                    )
                                    if deleted:
                                        self.logger.info(f"Snapshot cleanup: {deleted} old port_snapshot rows deleted")
                                self.logger.debug("Periodic cleanup completed")
                        except Exception as e:
                            self.logger.error(f"Cleanup hatası: {e}", exc_info=True)
                    
                except Exception as e:
                    self.logger.error(f"Döngü hatası: {e}", exc_info=True)
                
                # Bir sonraki döngüye kadar bekle.
                # interval, TÜM döngünün (SNMP + DB) süresinden büyükse
                # kalan süre kadar uyur; böylece işlemci gerçekten dinlenir.
                if self.running:
                    elapsed = time.time() - cycle_start
                    wait = max(0.0, self.config.polling.interval - elapsed)
                    if wait > 0:
                        self.logger.debug(
                            f"Sonraki döngüye {wait:.1f}s bekleniyor "
                            f"(döngü süresi: {elapsed:.1f}s, interval: {self.config.polling.interval}s)"
                        )
                        # Interruptible sleep: wakes immediately when stop() is called.
                        # We do NOT clear the event — self.running is already False
                        # when stop() sets it, so the while-loop exits on the next
                        # iteration regardless.
                        self._stop_event.wait(timeout=wait)
                    else:
                        self.logger.warning(
                            f"Döngü süresi ({elapsed:.1f}s) interval'den "
                            f"({self.config.polling.interval}s) uzun! "
                            "interval değerini artırmayı düşünün."
                        )
        
        except Exception as e:
            self.logger.error(f"Ana döngüde kritik hata: {e}", exc_info=True)
            return 1
        
        finally:
            self.shutdown()
        
        return 0
    
    def shutdown(self):
        """Perform cleanup on shutdown."""
        self.logger.warning("SNMP Worker shutting down")

        # Close database connections
        if self.db_manager and self.db_manager.engine:
            self.db_manager.engine.dispose()

        # Flush and stop the background log queue listener
        stop_listener()


def main():
    """Main entry point."""
    try:
        import argparse
        
        parser = argparse.ArgumentParser(
            description="SNMP Worker - Network Monitoring System"
        )
        parser.add_argument(
            '-c', '--config',
            help='Path to configuration file',
            default=None
        )
        
        args = parser.parse_args()
        
        # Create and run worker
        worker = SNMPWorker(config_file=args.config)
        sys.exit(worker.run())
        
    except Exception as e:
        print("\n" + "="*60)
        print("HATA: Worker baslatilirken hata olustu!")
        print("="*60)
        print(f"\nHata: {e}")
        print(f"Hata tipi: {type(e).__name__}")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user (Ctrl+C)")
        sys.exit(0)
    except SystemExit:
        # Normal exit, re-raise
        raise
    except Exception as e:
        # Catch any uncaught exception at the top level
        print("\n" + "="*60)
        print("KRITIK HATA: Beklenmeyen hata olustu!")
        print("="*60)
        print(f"\nHata: {e}")
        print(f"Hata tipi: {type(e).__name__}")
        print("\nLutfen bu hatayi raporlayin:")
        print("  1. Yukaridaki hata mesajini kaydedin")
        print("  2. Log dosyasini kontrol edin: logs/snmp_worker.log")
        print("  3. Config dosyasini kontrol edin: config/config.yml")
        print("\n" + "="*60 + "\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
