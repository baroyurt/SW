"""
Configuration loader for SNMP Worker.
Supports YAML configuration files and environment variable overrides.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field

# Optional: Try to load dotenv for environment variable support
try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False
    load_dotenv = None


@dataclass
class DatabaseConfig:
    """Database configuration."""
    host: str = "localhost"
    port: int = 1433
    name: str = "switchdb"
    user: str = ""
    password: str = ""
    pool_size: int = 10
    max_overflow: int = 20


@dataclass
class SNMPConfig:
    """SNMP configuration."""
    timeout: int = 5
    retries: int = 3
    max_bulk_size: int = 50


@dataclass
class PollingConfig:
    """Polling configuration."""
    interval: int = 30
    parallel_devices: int = 5
    max_workers: int = 10
    # Milliseconds to wait between launching each SNMP thread in Phase 1.
    # Spreading launches reduces instantaneous CPU and network burst load.
    # 0 = no stagger (original behaviour).
    snmp_stagger_ms: int = 0
    # Maximum number of parallel DB writer threads in Phase 2.
    # Lower values reduce CPU spikes during the DB-write phase.
    # 0 = auto (max_workers // 2, at least 4).
    db_max_workers: int = 0
    # Days to keep port_snapshot rows.  With the UPSERT design (one row per
    # port) this only affects decommissioned / disabled device rows.
    snapshot_retention_days: int = 15
    # Minimum seconds between successive device_polling_data INSERTs for the
    # same device.  A new row is always inserted on a success↔failure status
    # transition regardless of this interval; in between, the row is only
    # written once every polling_data_interval seconds.
    # Default: 60 s → 1 row/min instead of 1 row/poll; reduces DB growth 4×
    # for the default 15 s poll interval without affecting dashboard accuracy.
    # Set to 0 to restore the old behaviour (insert every poll).
    polling_data_interval: int = 60
    # Days to retain device_polling_data rows.  Older rows are deleted by the
    # periodic cleanup that runs every ~25 minutes.  7 days is sufficient for
    # the health trend charts (which query up to 168 h = 7 days).
    polling_data_retention_days: int = 7
    # Minimum seconds between successive MAC address table SNMP walks for
    # each device.  On intermediate cycles the last MAC table is reused.
    # Status transitions (port up/down) reset the MAC cache for that device
    # so a fresh MAC walk is always done when a port comes back up.
    # Default: 60 s (every 4 cycles at 15 s poll interval).
    # Set to 0 to walk the MAC table on every poll (original behaviour).
    # Reduces C9200 VLAN-context PDUs ~75%; CBS350 FDB walk ~75%.
    mac_poll_interval: int = 60
    # Minimum seconds between successive SNMP device-info collections
    # (sysDescr, temperature, fan, PoE, CPU) for each device.
    # On intermediate cycles the cached DeviceInfo is reused, so the
    # snmp_devices table still receives fresh-enough environmental values.
    # Default: 60 s.  Set to 0 to poll every cycle (original behaviour).
    # Reduces CBS350 load ~17% (saves 1 scalar GET + 4 env table walks
    # per non-poll cycle).
    device_info_poll_interval: int = 60
    # Minimum seconds between successive port-status SNMP walks (ifTable,
    # ifOperStatus, ifAdminStatus, dot1qPvid) for each device.
    # On intermediate cycles the cached port list is used; DB port_status_data
    # rows and alarm checks are skipped until fresh data arrives.
    # Alarm detection latency = at most port_poll_interval seconds.
    # Default: 15 s (every cycle – original behaviour).
    # Set to 60 s to reduce switch ifTable walk load by ~75%.
    # Set to 0 to poll every cycle (same as default).
    port_poll_interval: int = 15


@dataclass
class AlarmConfig:
    """Alarm configuration."""
    enabled: bool = True
    debounce_time: int = 60
    trigger_on: list[str] = field(default_factory=lambda: ["port_down", "device_unreachable", "snmp_error"])
    # Minimum consecutive poll failures before a device_unreachable alarm is raised.
    # Prevents instant false alarms when a switch is newly added to the config.
    unreachable_threshold: int = 3
    # When non-empty, port_down/port_up alarms are suppressed for ports whose
    # access VLAN is in this list.  An empty list means "no exclusion — alert all".
    vlan_exclude: list[int] = field(default_factory=list)


@dataclass
class TelegramConfig:
    """Telegram notification configuration."""
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""
    notify_on: list[str] = field(default_factory=lambda: ["port_down", "port_up", "device_unreachable", "mac_moved", "mac_added"])


@dataclass
class EmailConfig:
    """Email notification configuration."""
    enabled: bool = False
    smtp_host: str = "smtp.yandex.com.tr"
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_password: str = ""
    from_address: str = ""
    to_addresses: list[str] = field(default_factory=list)
    notify_on: list[str] = field(default_factory=lambda: ["port_down", "device_unreachable", "mac_moved", "mac_added"])
    smtp_ssl_verify: bool = False  # Set True in production with valid TLS certificates


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "WARNING"
    format: str = "text"
    file: str = "logs/snmp_worker.log"
    max_bytes: int = 5242880
    backup_count: int = 2
    console: bool = False


@dataclass
class DeviceConfig:
    """Device configuration."""
    name: str
    ip: str
    vendor: str
    model: str
    snmp_version: str = "2c"
    community: str = "public"
    enabled: bool = True
    snmp_v3: Optional[Dict[str, str]] = None
    engine_id: Optional[str] = None  # SNMPv3 Engine ID
    # Port numaralarının listesi. Dolu ise sadece bu portlar için port_down alarmı
    # üretilir; diğer portların kapanması alarm oluşturmaz.
    # Boş liste (varsayılan) = tüm portlar izlenir.
    monitored_ports: list = field(default_factory=list)
    # MAC tablosu taramasından hariç tutulacak port numaraları.
    # Uplink/trunk portlar gibi tüm switch MAC'lerini duyabilen portlar için
    # kullanılır; bu portlara atanan MAC'ler DB'ye yazılmaz, deadlock riski azalır.
    # Boş liste (varsayılan) = tüm portların MAC'leri işlenir.
    mac_exclude_ports: list = field(default_factory=list)


class Config:
    """Main configuration class."""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Path to YAML configuration file
        """
        # Load environment variables if dotenv is available
        if DOTENV_AVAILABLE and load_dotenv:
            load_dotenv()
        
        # Determine config file path
        if config_file is None:
            # Try different possible locations
            possible_paths = [
                Path("config/config.yml"),  # Running from snmp_worker directory
                Path("snmp_worker/config/config.yml"),  # Running from parent
                Path(__file__).parent / "config.yml",  # Same directory as config_loader.py
            ]
            
            config_file = None
            for path in possible_paths:
                if path.exists():
                    config_file = str(path)
                    break
            
            # Fallback to environment variable or default
            if config_file is None:
                config_file = os.getenv("SNMP_CONFIG_FILE", "config/config.yml")
        
        self.config_file = Path(config_file)
        self._config_data: Dict[str, Any] = {}
        
        # Load configuration
        self._load_config()
        
        # Initialize configuration objects
        self.database = self._init_database_config()
        self.snmp = self._init_snmp_config()
        self.polling = self._init_polling_config()
        self.alarms = self._init_alarm_config()
        self.telegram = self._init_telegram_config()
        self.email = self._init_email_config()
        self.logging = self._init_logging_config()
        self.devices = self._init_devices_config()
    
    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self._config_data = yaml.safe_load(f) or {}
        else:
            # Use example config if no config file exists
            example_config = self.config_file.parent / "config.example.yml"
            if example_config.exists():
                print(f"Warning: Config file {self.config_file} not found. Using example config.")
                with open(example_config, 'r') as f:
                    self._config_data = yaml.safe_load(f) or {}
            else:
                print(f"Warning: No configuration file found. Using defaults.")
                self._config_data = {}
    
    def _get_env_or_config(self, env_key: str, config_path: list[str], default: Any = None) -> Any:
        """
        Get value from environment variable or config file.
        Environment variables take precedence.
        
        Args:
            env_key: Environment variable name
            config_path: Path to config value (e.g., ['database', 'host'])
            default: Default value if not found
            
        Returns:
            Configuration value
        """
        # Check environment variable first
        env_value = os.getenv(env_key)
        if env_value is not None:
            return env_value
        
        # Check config file
        value = self._config_data
        for key in config_path:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value if value is not None else default
    
    def _init_database_config(self) -> DatabaseConfig:
        """Initialize database configuration."""
        return DatabaseConfig(
            host=self._get_env_or_config("DB_HOST", ["database", "host"], "MANAGEENGINE\\SQLEXPRESS"),
            port=int(self._get_env_or_config("DB_PORT", ["database", "port"], 1433)),
            name=self._get_env_or_config("DB_NAME", ["database", "name"], "switchdb"),
            user=self._get_env_or_config("DB_USER", ["database", "user"], ""),
            password=self._get_env_or_config("DB_PASSWORD", ["database", "password"], ""),
            pool_size=int(self._get_env_or_config("DB_POOL_SIZE", ["database", "pool_size"], 10)),
            max_overflow=int(self._get_env_or_config("DB_MAX_OVERFLOW", ["database", "max_overflow"], 20))
        )
    
    def _init_snmp_config(self) -> SNMPConfig:
        """Initialize SNMP configuration."""
        snmp_data = self._config_data.get("snmp", {})
        return SNMPConfig(
            timeout=snmp_data.get("timeout", 5),
            retries=snmp_data.get("retries", 3),
            max_bulk_size=snmp_data.get("max_bulk_size", 50)
        )
    
    def _init_polling_config(self) -> PollingConfig:
        """Initialize polling configuration."""
        polling_data = self._config_data.get("polling", {})

        def _int_field(key: str, default: int) -> int:
            raw = polling_data.get(key, default)
            try:
                return int(raw)
            except (TypeError, ValueError):
                raise ValueError(
                    f"polling.{key} must be an integer, got: {raw!r}"
                )

        return PollingConfig(
            interval=int(self._get_env_or_config("POLL_INTERVAL", ["polling", "interval"], 30)),
            parallel_devices=polling_data.get("parallel_devices", 5),
            max_workers=polling_data.get("max_workers", 10),
            snmp_stagger_ms=_int_field("snmp_stagger_ms", 0),
            db_max_workers=_int_field("db_max_workers", 0),
            snapshot_retention_days=_int_field("snapshot_retention_days", 15),
            polling_data_interval=_int_field("polling_data_interval", 60),
            polling_data_retention_days=_int_field("polling_data_retention_days", 7),
            mac_poll_interval=_int_field("mac_poll_interval", 60),
            device_info_poll_interval=_int_field("device_info_poll_interval", 60),
            port_poll_interval=_int_field("port_poll_interval", 15),
        )
    
    def _init_alarm_config(self) -> AlarmConfig:
        """Initialize alarm configuration."""
        alarm_data = self._config_data.get("alarms", {})
        return AlarmConfig(
            enabled=alarm_data.get("enabled", True),
            debounce_time=alarm_data.get("debounce_time", 60),
            trigger_on=alarm_data.get("trigger_on", ["port_down", "device_unreachable", "snmp_error"]),
            unreachable_threshold=int(alarm_data.get("unreachable_threshold", 3)),
            vlan_exclude=[int(v) for v in alarm_data.get("vlan_exclude", [])]
        )
    
    def _init_telegram_config(self) -> TelegramConfig:
        """Initialize Telegram configuration."""
        telegram_data = self._config_data.get("telegram", {})
        return TelegramConfig(
            enabled=telegram_data.get("enabled", False),
            bot_token=self._get_env_or_config("TELEGRAM_BOT_TOKEN", ["telegram", "bot_token"], ""),
            chat_id=self._get_env_or_config("TELEGRAM_CHAT_ID", ["telegram", "chat_id"], ""),
            notify_on=telegram_data.get("notify_on", ["port_down", "port_up", "device_unreachable", "mac_moved", "mac_added"])
        )
    
    def _init_email_config(self) -> EmailConfig:
        """Initialize email configuration."""
        email_data = self._config_data.get("email", {})
        return EmailConfig(
            enabled=email_data.get("enabled", False),
            smtp_host=email_data.get("smtp_host", "smtp.yandex.com.tr"),
            smtp_port=email_data.get("smtp_port", 465),
            smtp_user=self._get_env_or_config("SMTP_USER", ["email", "smtp_user"], ""),
            smtp_password=self._get_env_or_config("SMTP_PASSWORD", ["email", "smtp_password"], ""),
            from_address=email_data.get("from_address", ""),
            to_addresses=email_data.get("to_addresses", []),
            notify_on=email_data.get("notify_on", ["port_down", "device_unreachable", "mac_moved", "mac_added"]),
            smtp_ssl_verify=email_data.get("smtp_ssl_verify", False)
        )
    
    def _init_logging_config(self) -> LoggingConfig:
        """Initialize logging configuration."""
        logging_data = self._config_data.get("logging", {})
        return LoggingConfig(
            level=self._get_env_or_config("LOG_LEVEL", ["logging", "level"], "WARNING"),
            format=logging_data.get("format", "text"),
            file=logging_data.get("file", "logs/snmp_worker.log"),
            max_bytes=logging_data.get("max_bytes", 5242880),
            backup_count=logging_data.get("backup_count", 2),
            console=logging_data.get("console", False)
        )
    
    def _init_devices_config(self) -> list[DeviceConfig]:
        """
        Initialize devices configuration from either 'devices' or 'switches' key.
        Supports both 'ip' and 'host' for device address for backward compatibility.
        """
        # Support both 'devices' and 'switches' keywords for backward compatibility
        devices_data = self._config_data.get("devices", [])
        if not devices_data:
            # Try 'switches' keyword (common in network monitoring configs)
            devices_data = self._config_data.get("switches", [])
        
        devices = []
        
        snmp_global = self._config_data.get("snmp", {})
        global_auth_pass = self._get_env_or_config(
            "SNMP_AUTH_PASSWORD", ["snmp", "auth_password"], snmp_global.get("auth_password", "")
        )
        global_priv_pass = self._get_env_or_config(
            "SNMP_PRIV_PASSWORD", ["snmp", "priv_password"], snmp_global.get("priv_password", "")
        )

        for device_data in devices_data:
            raw_monitored = device_data.get("monitored_ports", [])
            monitored_ports = [int(p) for p in raw_monitored] if raw_monitored else []
            raw_mac_exclude = device_data.get("mac_exclude_ports", [])
            mac_exclude_ports = [int(p) for p in raw_mac_exclude] if raw_mac_exclude else []

            # Apply global SNMP credential env-vars to per-device snmp_v3 blocks
            # when the per-device value is explicitly empty.
            snmp_v3 = device_data.get("snmp_v3")
            if snmp_v3 is not None:
                snmp_v3 = dict(snmp_v3)  # avoid mutating the original
                if not snmp_v3.get("auth_password") and global_auth_pass:
                    snmp_v3["auth_password"] = global_auth_pass
                if not snmp_v3.get("priv_password") and global_priv_pass:
                    snmp_v3["priv_password"] = global_priv_pass

            device = DeviceConfig(
                name=device_data.get("name", "Unknown"),
                # Support both 'ip' and 'host' keywords
                ip=device_data.get("ip") or device_data.get("host", ""),
                vendor=device_data.get("vendor", ""),
                model=device_data.get("model", ""),
                snmp_version=device_data.get("snmp_version", "2c"),
                community=device_data.get("community", "public"),
                enabled=device_data.get("enabled", True),
                snmp_v3=snmp_v3,
                engine_id=device_data.get("snmp_engine_id") or device_data.get("engine_id"),  # Support both formats
                monitored_ports=monitored_ports,
                mac_exclude_ports=mac_exclude_ports,
            )
            devices.append(device)
        
        return devices
    
    def _get_mssql_odbc_driver(self) -> str:
        """
        Return the best available SQL Server ODBC driver name.

        Checks pyodbc.drivers() at runtime and picks the highest-version
        driver that is actually installed on the machine.  Falls back to
        'ODBC Driver 17 for SQL Server' if pyodbc is not yet importable
        (e.g. still being installed) so the error message stays meaningful.
        """
        preferred = [
            "ODBC Driver 18 for SQL Server",
            "ODBC Driver 17 for SQL Server",
            "ODBC Driver 13 for SQL Server",
            "SQL Server Native Client 11.0",
            "SQL Server",
        ]
        try:
            import pyodbc
            available = set(pyodbc.drivers())
            for driver in preferred:
                if driver in available:
                    return driver
            # Last resort: any driver whose name contains "SQL Server"
            fallbacks = sorted(d for d in available if "SQL Server" in d)
            if fallbacks:
                return fallbacks[-1]
        except Exception:
            pass
        return "ODBC Driver 17 for SQL Server"

    def get_database_url(self) -> str:
        """Get database connection URL."""
        # SQL Server: named instance (backslash) or port 1433
        if '\\' in self.database.host or self.database.port == 1433:
            driver = self._get_mssql_odbc_driver()
            if not self.database.user and not self.database.password:
                # Windows Authentication
                odbc = (
                    f"DRIVER={{{driver}}};"
                    f"SERVER={self.database.host};"
                    f"DATABASE={self.database.name};"
                    f"Trusted_Connection=yes;"
                    f"TrustServerCertificate=yes"
                )
            else:
                # SQL Server Authentication
                odbc = (
                    f"DRIVER={{{driver}}};"
                    f"SERVER={self.database.host};"
                    f"DATABASE={self.database.name};"
                    f"UID={self.database.user};"
                    f"PWD={self.database.password};"
                    f"TrustServerCertificate=yes"
                )
            return f"mssql+pyodbc:///?odbc_connect={odbc}"

        # PostgreSQL fallback
        if self.database.port == 5432:
            db_type = "postgresql"
            password = self.database.password.replace('@', '%40').replace(':', '%3A')
            return (
                f"{db_type}://{self.database.user}:{password}"
                f"@{self.database.host}:{self.database.port}/{self.database.name}"
            )

        raise ValueError(
            f"Unsupported database host/port: {self.database.host}:{self.database.port}. "
            "For SQL Server use host with backslash (e.g. SERVER\\INSTANCE) or port 1433."
        )
