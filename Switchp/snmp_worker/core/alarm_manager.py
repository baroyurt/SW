"""
Alarm manager for detecting and managing alarms.
Implements state-based alarm detection to prevent duplicates.
"""

import logging
from typing import Optional, Dict, Set
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from models.database import (
    SNMPDevice, PortStatusData, Alarm, AlarmSeverity, AlarmStatus, PortStatus
)
from core.database_manager import DatabaseManager
from services.telegram_service import TelegramNotificationService
from services.email_service import EmailNotificationService
from config.config_loader import Config


class AlarmManager:
    """
    Alarm manager for detecting and managing network alarms.
    Implements debouncing to prevent alarm flooding.
    """
    
    def __init__(
        self,
        config: Config,
        db_manager: DatabaseManager,
        telegram_service: Optional[TelegramNotificationService] = None,
        email_service: Optional[EmailNotificationService] = None
    ):
        """
        Initialize alarm manager.
        
        Args:
            config: Configuration object
            db_manager: Database manager
            telegram_service: Telegram notification service
            email_service: Email notification service
        """
        self.config = config
        self.db_manager = db_manager
        self.telegram_service = telegram_service
        self.email_service = email_service
        self.logger = logging.getLogger('snmp_worker.alarm_manager')
        
        # Track recent notifications to implement debouncing
        self._recent_notifications: Dict[str, datetime] = {}
        self._debounce_seconds = config.alarms.debounce_time
        
        # Track port states
        self._port_states: Dict[tuple, PortStatus] = {}  # (device_id, port_number) -> status
        
        self.logger.info("Alarm manager initialized")
    
    def _should_notify(self, alarm_key: str) -> bool:
        """
        Check if notification should be sent based on debounce time.
        
        Args:
            alarm_key: Unique key for the alarm
            
        Returns:
            True if notification should be sent, False otherwise
        """
        if alarm_key not in self._recent_notifications:
            return True
        
        last_notification = self._recent_notifications[alarm_key]
        time_since_last = (datetime.utcnow() - last_notification).total_seconds()
        
        return time_since_last >= self._debounce_seconds
    
    def _mark_notified(self, alarm_key: str) -> None:
        """
        Mark that a notification was sent for an alarm.
        
        Args:
            alarm_key: Unique key for the alarm
        """
        self._recent_notifications[alarm_key] = datetime.utcnow()
    
    def _send_notifications(
        self,
        device: SNMPDevice,
        alarm_type: str,
        severity: str,
        message: str,
        port_number: Optional[int] = None,
        port_name: Optional[str] = None
    ) -> None:
        """
        Send notifications via configured channels.
        
        Args:
            device: Device
            alarm_type: Type of alarm
            severity: Alarm severity as UPPERCASE string
            message: Alarm message
            port_number: Port number (for port-specific alarms)
            port_name: Port name (for port-specific alarms)
        """
        # Severity zaten büyük harf olarak gelmeli
        severity_upper = severity.upper() if severity else "MEDIUM"
        
        # Check if this alarm type should trigger notifications
        telegram_notify = (
            self.telegram_service 
            and self.config.telegram.enabled 
            and alarm_type in self.config.telegram.notify_on
        )
        
        email_notify = (
            self.email_service 
            and self.config.email.enabled 
            and alarm_type in self.config.email.notify_on
        )
        
        # Send Telegram notification
        if telegram_notify:
            try:
                if alarm_type == "port_down" and port_number:
                    self.telegram_service.send_port_down(
                        device.name, device.ip_address, port_number, port_name or ""
                    )
                elif alarm_type == "port_up" and port_number:
                    self.telegram_service.send_port_up(
                        device.name, device.ip_address, port_number, port_name or ""
                    )
                elif alarm_type == "device_unreachable":
                    self.telegram_service.send_device_unreachable(
                        device.name, device.ip_address
                    )
                else:
                    self.telegram_service.send_alarm(
                        device.name, device.ip_address, alarm_type, severity_upper, message
                    )
            except Exception as e:
                self.logger.error(f"Failed to send Telegram notification: {e}")
        
        # Send email notification
        if email_notify:
            try:
                if alarm_type == "port_down" and port_number:
                    self.email_service.send_port_down(
                        device.name, device.ip_address, port_number, port_name or ""
                    )
                elif alarm_type == "device_unreachable":
                    self.email_service.send_device_unreachable(
                        device.name, device.ip_address
                    )
                else:
                    self.email_service.send_alarm(
                        device.name, device.ip_address, alarm_type, severity_upper, message
                    )
            except Exception as e:
                self.logger.error(f"Failed to send email notification: {e}")
    
    def check_device_reachability(
        self,
        session: Session,
        device: SNMPDevice,
        is_reachable: bool
    ) -> None:
        """
        Check device reachability and create/resolve alarms.
        
        Args:
            session: Database session
            device: Device to check
            is_reachable: Whether device is reachable
        """
        alarm_type = "device_unreachable"
        alarm_key = f"{device.id}_{alarm_type}"
        
        if not is_reachable:
            # ★★★ FORCE DEBUG ★★★
            print("\n" + "="*60)
            print("🔵🔵🔵 ALARM MANAGER - Device Unreachable")
            print("="*60)
            print(f"🔵 Device    : {device.name} ({device.ip_address})")
            print(f"🔵 Alarm Tipi: {alarm_type}")
            print(f"🔵 Severity  : CRITICAL")
            print("="*60 + "\n")
            
            # Device is unreachable - create alarm
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                alarm_type,
                "CRITICAL",  # String olarak büyük harf
                f"Device {device.name} is unreachable",
                f"Device {device.name} ({device.ip_address}) is not responding to SNMP requests."
            )
            
            # Send notification if it's a new alarm and debounce allows
            if is_new and self._should_notify(alarm_key):
                self._send_notifications(
                    device, 
                    alarm_type, 
                    "CRITICAL",
                    f"Device is not responding to SNMP requests."
                )
                alarm.notification_sent = True
                alarm.last_notification_sent = datetime.utcnow()
                self._mark_notified(alarm_key)
                self.logger.warning(f"Device {device.name} is unreachable - alarm raised")
        else:
            # Device is reachable - resolve any active alarms
            active_alarms = session.query(Alarm).filter(
                Alarm.device_id == device.id,
                Alarm.alarm_type == alarm_type,
                Alarm.status == AlarmStatus.ACTIVE
            ).all()
            
            for alarm in active_alarms:
                self.db_manager.resolve_alarm(session, alarm, "Device is now reachable")
                self.logger.info(f"Device {device.name} is reachable - alarm resolved")
    
    def check_port_status(
        self,
        session: Session,
        device: SNMPDevice,
        port_number: int,
        port_name: str,
        admin_status: PortStatus,
        oper_status: PortStatus
    ) -> None:
        """
        Check port status and create/resolve alarms based on state changes.
        
        Args:
            session: Database session
            device: Device
            port_number: Port number
            port_name: Port name
            admin_status: Administrative status
            oper_status: Operational status
        """
        state_key = (device.id, port_number)
        previous_status = self._port_states.get(state_key)
        
        # Update current state
        self._port_states[state_key] = oper_status
        
        # Check if this is a state change
        if previous_status is None:
            # First time seeing this port, don't trigger alarm
            return
        
        if previous_status == oper_status:
            # No state change
            return
        
        # State changed
        if oper_status == PortStatus.DOWN and admin_status == PortStatus.UP:
            # Port went down (but is administratively up) - create alarm
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                "port_down",
                "HIGH",
                f"Port {port_number} kapandı",
                f"{device.name} Port {port_number} ({port_name}) bağlantısı kesildi.",
                port_number=port_number
            )
            
            alarm_key = f"{device.id}_port_{port_number}_port_down"
            
            # Send notification if debounce allows
            if self._should_notify(alarm_key):
                self._send_notifications(
                    device, 
                    "port_down", 
                    "HIGH",
                    f"Port {port_number} ({port_name}) bağlantısı kesildi.",
                    port_number=port_number,
                    port_name=port_name
                )
                alarm.notification_sent = True
                alarm.last_notification_sent = datetime.utcnow()
                self._mark_notified(alarm_key)
                self.logger.warning(f"Port {port_number} on {device.name} went down")
        
        elif oper_status == PortStatus.UP and previous_status == PortStatus.DOWN:
            # Port came up - resolve alarm
            active_alarms = session.query(Alarm).filter(
                Alarm.device_id == device.id,
                Alarm.alarm_type == "port_down",
                Alarm.port_number == port_number,
                Alarm.status == AlarmStatus.ACTIVE
            ).all()
            
            for alarm in active_alarms:
                self.db_manager.resolve_alarm(session, alarm, "Port is now up")
                self.logger.info(f"Port {port_number} on {device.name} came up - alarm resolved")
            
            # Optionally send "port up" notification
            alarm_key = f"{device.id}_port_{port_number}_port_up"
            if ("port_up" in self.config.telegram.notify_on or 
                "port_up" in self.config.email.notify_on):
                if self._should_notify(alarm_key):
                    self._send_notifications(
                        device, 
                        "port_up", 
                        "INFO",
                        f"Port {port_number} ({port_name}) is now up.",
                        port_number=port_number,
                        port_name=port_name
                    )
                    self._mark_notified(alarm_key)
    
    def cleanup_old_notifications(self, hours: int = 24) -> None:
        """
        Clean up old notification timestamps.
        
        Args:
            hours: Number of hours to keep
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        keys_to_remove = [
            key for key, timestamp in self._recent_notifications.items()
            if timestamp < cutoff
        ]
        for key in keys_to_remove:
            del self._recent_notifications[key]
        
        if keys_to_remove:
            self.logger.debug(f"Cleaned up {len(keys_to_remove)} old notification timestamps")