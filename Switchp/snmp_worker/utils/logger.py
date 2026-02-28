"""
Logging configuration for SNMP Worker.
Supports both JSON and text format logging.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger
from typing import Optional


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields."""
    
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        if hasattr(record, 'device_name'):
            log_record['device_name'] = record.device_name
        if hasattr(record, 'device_ip'):
            log_record['device_ip'] = record.device_ip


def setup_logging(
    log_level: str = "INFO",
    log_format: str = "json",
    log_file: Optional[str] = None,
    max_bytes: int = 10485760,
    backup_count: int = 5,
    console: bool = True
) -> logging.Logger:
    """
    Setup logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format (json or text)
        log_file: Path to log file
        max_bytes: Maximum bytes per log file
        backup_count: Number of backup files to keep
        console: Whether to log to console
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger('snmp_worker')
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    logger.handlers.clear()
    
    # Create formatters
    if log_format == "json":
        formatter = CustomJsonFormatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    # Add file handler if log file specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Add console handler if enabled
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger


def get_logger(name: str = 'snmp_worker') -> logging.Logger:
    """
    Get logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class DeviceLoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter that adds device information to log records.
    """
    
    def __init__(self, logger: logging.Logger, device_name: str, device_ip: str):
        """
        Initialize adapter.
        
        Args:
            logger: Base logger
            device_name: Device name
            device_ip: Device IP address
        """
        super().__init__(logger, {})
        self.device_name = device_name
        self.device_ip = device_ip
    
    def process(self, msg, kwargs):
        """Add device information to log record."""
        # Add device info to extra
        extra = kwargs.get('extra', {})
        extra['device_name'] = self.device_name
        extra['device_ip'] = self.device_ip
        kwargs['extra'] = extra
        
        # Prefix message with device info for text format
        msg = f"[{self.device_name}@{self.device_ip}] {msg}"
        
        return msg, kwargs
