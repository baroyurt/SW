"""
Logging configuration for SNMP Worker.
Supports both JSON and text format logging.

All file/console I/O is performed by a dedicated background thread via
QueueHandler + QueueListener (Python 3.2+).  Polling threads only enqueue
a log record (in-memory) and return immediately – disk I/O never blocks
the SNMP or DB worker threads.
"""

import logging
import queue
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener
from typing import Optional, List

# pythonjsonlogger is optional – only needed when format == "json"
try:
    from pythonjsonlogger import jsonlogger as _jsonlogger

    class CustomJsonFormatter(_jsonlogger.JsonFormatter):
        """Custom JSON formatter with additional fields."""

        def add_fields(self, log_record, record, message_dict):
            super().add_fields(log_record, record, message_dict)
            log_record['level'] = record.levelname
            log_record['logger'] = record.name
            if hasattr(record, 'device_name'):
                log_record['device_name'] = record.device_name
            if hasattr(record, 'device_ip'):
                log_record['device_ip'] = record.device_ip

except ImportError:
    _jsonlogger = None
    CustomJsonFormatter = None  # type: ignore[assignment,misc]

# Module-level reference so the listener can be stopped on shutdown
_queue_listener: Optional[QueueListener] = None


def stop_listener() -> None:
    """Stop the background QueueListener if it is running."""
    global _queue_listener
    if _queue_listener is not None:
        _queue_listener.stop()
        _queue_listener = None


def setup_logging(
    log_level: str = "WARNING",
    log_format: str = "text",
    log_file: Optional[str] = None,
    max_bytes: int = 10485760,
    backup_count: int = 5,
    console: bool = False
) -> logging.Logger:
    """
    Setup logging configuration.

    All actual I/O is offloaded to a background QueueListener thread so
    that polling threads are never blocked by disk writes.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
                   Default WARNING – only problems are recorded.
        log_format: Log format ('json' or 'text').  'text' is faster.
        log_file: Path to log file (None = no file handler).
        max_bytes: Maximum bytes per log file before rotation.
        backup_count: Number of rotated backup files to keep.
        console: Whether to log to stdout (disable for service mode).

    Returns:
        Configured logger instance
    """
    global _queue_listener

    # Stop any previous listener before reconfiguring
    stop_listener()

    logger = logging.getLogger('snmp_worker')
    logger.setLevel(getattr(logging, log_level.upper(), logging.WARNING))
    logger.handlers.clear()
    # Prevent records from leaking to the root logger (which may have been
    # configured at DEBUG/INFO by a third-party library via basicConfig).
    logger.propagate = False

    # ── Build real (downstream) handlers ──────────────────────────────────
    if log_format == "json" and CustomJsonFormatter is not None:
        formatter: logging.Formatter = CustomJsonFormatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    downstream_handlers: List[logging.Handler] = []

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8',
        )
        file_handler.setFormatter(formatter)
        downstream_handlers.append(file_handler)

    if console and sys.stdout is not None:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        downstream_handlers.append(console_handler)

    # ── Wrap with async queue handler ──────────────────────────────────────
    # Even if there are no downstream handlers (e.g. pure service mode with
    # logging disabled), add a NullHandler so the logger is happy.
    if downstream_handlers:
        # Bounded queue: at WARNING level with 38 devices the queue should
        # never exceed a handful of entries.  1 000 records is ample headroom
        # while still failing fast if something floods the log unexpectedly.
        log_queue: queue.Queue = queue.Queue(maxsize=1_000)
        queue_handler = QueueHandler(log_queue)
        logger.addHandler(queue_handler)

        _queue_listener = QueueListener(
            log_queue,
            *downstream_handlers,
            respect_handler_level=True,
        )
        _queue_listener.start()
    else:
        logger.addHandler(logging.NullHandler())

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
