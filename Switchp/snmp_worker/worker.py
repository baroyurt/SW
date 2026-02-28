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
        import pymysql
    except ImportError:
        missing.append("pymysql")
    
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
        print("  - pymysql paketi eksik")
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
        from utils.logger import setup_logging
        modules_to_import.append(("setup_logging", setup_logging))
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


class SNMPWorker:
    """Main SNMP Worker daemon."""
    
    def __init__(self, config_file: str = None):
        """
        Initialize SNMP Worker.
        
        Args:
            config_file: Path to configuration file
        """
        self.running = False
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
            print(f"Error loading configuration: {e}")
            sys.exit(1)
        
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
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
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
                    enabled=self.config.email.enabled
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
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            raise
    
    def _signal_handler(self, signum, frame):
        """
        Handle shutdown signals.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        signal_names = {
            signal.SIGINT: "SIGINT",
            signal.SIGTERM: "SIGTERM"
        }
        signal_name = signal_names.get(signum, str(signum))
        
        self.logger.info(f"Received {signal_name}, shutting down gracefully...")
        self.running = False
    
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
                self.logger.info(f"Starting poll cycle #{cycle_count}")
                
                try:
                    # Poll all devices
                    results = self.polling_engine.poll_all_devices()
                    
                    # Log summary
                    successful = sum(1 for r in results if r['success'])
                    failed = len(results) - successful
                    self.logger.info(
                        f"Poll cycle #{cycle_count} complete: "
                        f"{successful} successful, {failed} failed"
                    )
                    
                    # Auto sync to main switches table after successful polling
                    if successful > 0:
                        try:
                            with self.db_manager.session_scope() as session:
                                sync_result = self.autosync_service.sync_all_devices(session)
                                if sync_result['success'] and sync_result['synced_count'] > 0:
                                    self.logger.info(
                                        f"Auto sync: {sync_result['synced_count']} device(s) synchronized to main database"
                                    )
                        except Exception as e:
                            self.logger.error(f"Auto sync failed: {e}", exc_info=True)
                    
                    # Cleanup old notification timestamps periodically
                    if cycle_count % 10 == 0:
                        self.alarm_manager.cleanup_old_notifications()
                    
                except Exception as e:
                    self.logger.error(f"Error in poll cycle: {e}", exc_info=True)
                
                # Wait for next poll interval
                if self.running:
                    self.logger.debug(f"Waiting {self.config.polling.interval} seconds until next poll")
                    time.sleep(self.config.polling.interval)
        
        except Exception as e:
            self.logger.error(f"Fatal error in main loop: {e}", exc_info=True)
            return 1
        
        finally:
            self.shutdown()
        
        return 0
    
    def shutdown(self):
        """Perform cleanup on shutdown."""
        self.logger.info("=" * 60)
        self.logger.info("SNMP Worker Shutting Down")
        self.logger.info("=" * 60)
        
        # Close database connections
        if self.db_manager and self.db_manager.engine:
            self.db_manager.engine.dispose()
            self.logger.info("Database connections closed")
        
        self.logger.info("Shutdown complete")


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
