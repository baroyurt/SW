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
    host: str = "127.0.0.1"
    port: int = 3306  # MySQL default (changed from 5432 PostgreSQL)
    name: str = "switchdb"
    user: str = "root"  # MySQL default (changed from postgres)
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


@dataclass
class AlarmConfig:
    """Alarm configuration."""
    enabled: bool = True
    debounce_time: int = 60
    trigger_on: list[str] = field(default_factory=lambda: ["port_down", "device_unreachable", "snmp_error"])


@dataclass
class TelegramConfig:
    """Telegram notification configuration."""
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""
    notify_on: list[str] = field(default_factory=lambda: ["port_down", "port_up", "device_unreachable"])


@dataclass
class EmailConfig:
    """Email notification configuration."""
    enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_address: str = ""
    to_addresses: list[str] = field(default_factory=list)
    notify_on: list[str] = field(default_factory=lambda: ["port_down", "device_unreachable"])


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    format: str = "json"
    file: str = "logs/snmp_worker.log"
    max_bytes: int = 10485760
    backup_count: int = 5
    console: bool = True


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
            host=self._get_env_or_config("DB_HOST", ["database", "host"], "127.0.0.1"),
            port=int(self._get_env_or_config("DB_PORT", ["database", "port"], 3306)),
            name=self._get_env_or_config("DB_NAME", ["database", "name"], "switchdb"),
            user=self._get_env_or_config("DB_USER", ["database", "user"], "root"),
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
        return PollingConfig(
            interval=int(self._get_env_or_config("POLL_INTERVAL", ["polling", "interval"], 30)),
            parallel_devices=polling_data.get("parallel_devices", 5),
            max_workers=polling_data.get("max_workers", 10)
        )
    
    def _init_alarm_config(self) -> AlarmConfig:
        """Initialize alarm configuration."""
        alarm_data = self._config_data.get("alarms", {})
        return AlarmConfig(
            enabled=alarm_data.get("enabled", True),
            debounce_time=alarm_data.get("debounce_time", 60),
            trigger_on=alarm_data.get("trigger_on", ["port_down", "device_unreachable", "snmp_error"])
        )
    
    def _init_telegram_config(self) -> TelegramConfig:
        """Initialize Telegram configuration."""
        telegram_data = self._config_data.get("telegram", {})
        return TelegramConfig(
            enabled=telegram_data.get("enabled", False),
            bot_token=self._get_env_or_config("TELEGRAM_BOT_TOKEN", ["telegram", "bot_token"], ""),
            chat_id=self._get_env_or_config("TELEGRAM_CHAT_ID", ["telegram", "chat_id"], ""),
            notify_on=telegram_data.get("notify_on", ["port_down", "port_up", "device_unreachable"])
        )
    
    def _init_email_config(self) -> EmailConfig:
        """Initialize email configuration."""
        email_data = self._config_data.get("email", {})
        return EmailConfig(
            enabled=email_data.get("enabled", False),
            smtp_host=email_data.get("smtp_host", "smtp.gmail.com"),
            smtp_port=email_data.get("smtp_port", 587),
            smtp_user=self._get_env_or_config("SMTP_USER", ["email", "smtp_user"], ""),
            smtp_password=self._get_env_or_config("SMTP_PASSWORD", ["email", "smtp_password"], ""),
            from_address=email_data.get("from_address", ""),
            to_addresses=email_data.get("to_addresses", []),
            notify_on=email_data.get("notify_on", ["port_down", "device_unreachable"])
        )
    
    def _init_logging_config(self) -> LoggingConfig:
        """Initialize logging configuration."""
        logging_data = self._config_data.get("logging", {})
        return LoggingConfig(
            level=self._get_env_or_config("LOG_LEVEL", ["logging", "level"], "INFO"),
            format=logging_data.get("format", "json"),
            file=logging_data.get("file", "logs/snmp_worker.log"),
            max_bytes=logging_data.get("max_bytes", 10485760),
            backup_count=logging_data.get("backup_count", 5),
            console=logging_data.get("console", True)
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
        
        for device_data in devices_data:
            device = DeviceConfig(
                name=device_data.get("name", "Unknown"),
                # Support both 'ip' and 'host' keywords
                ip=device_data.get("ip") or device_data.get("host", ""),
                vendor=device_data.get("vendor", ""),
                model=device_data.get("model", ""),
                snmp_version=device_data.get("snmp_version", "2c"),
                community=device_data.get("community", "public"),
                enabled=device_data.get("enabled", True),
                snmp_v3=device_data.get("snmp_v3"),
                engine_id=device_data.get("snmp_engine_id") or device_data.get("engine_id")  # Support both formats
            )
            devices.append(device)
        
        return devices
    
    def get_database_url(self) -> str:
        """
        Get database connection URL.
        Auto-detects database type by port number.
        
        Returns:
            Database connection URL (MySQL or PostgreSQL)
        """
        # Auto-detect database type by port
        if self.database.port == 3306:
            # MySQL/MariaDB
            db_type = "mysql+pymysql"
        elif self.database.port == 5432:
            # PostgreSQL
            db_type = "postgresql"
        else:
            # Default to MySQL if custom port
            db_type = "mysql+pymysql"
        
        # URL encode password if it contains special characters
        password = self.database.password.replace('@', '%40').replace(':', '%3A')
        
        return (
            f"{db_type}://{self.database.user}:{password}"
            f"@{self.database.host}:{self.database.port}/{self.database.name}"
        )
