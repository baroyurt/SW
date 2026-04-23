"""
Alarm manager for detecting and managing alarms.
Implements state-based alarm detection to prevent duplicates.
"""

import logging
from typing import Optional, Dict, Set
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import text

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
        
        # Cache of core ports: (device_id, port_number) -> core_switch_name.
        # Populated lazily from the snmp_core_ports DB table on first use and
        # refreshed every poll cycle so admin UI changes take effect quickly.
        self._core_ports: Dict[tuple, str] = {}
        self._core_ports_loaded_at: Optional[datetime] = None

        # Per-device monitored port sets.
        # device_name -> set of port numbers that should generate port_down alarms.
        # An empty set means ALL ports are monitored (no filtering).
        self._monitored_ports: Dict[str, Set[int]] = {
            dev.name: set(dev.monitored_ports)
            for dev in config.devices
            if dev.monitored_ports
        }
        
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
    
    def _get_alarm_severity(self, session: Session, alarm_type: str, default_severity: str = "MEDIUM") -> str:
        """
        Return the configured severity for an alarm type from alarm_severity_config.
        Falls back to *default_severity* if the row is missing or the query fails.
        """
        try:
            row = session.execute(
                text("SELECT severity FROM alarm_severity_config WHERE alarm_type = :t"),
                {"t": alarm_type}
            ).fetchone()
            if row:
                return str(row[0])
        except Exception as exc:
            self.logger.warning(f"Could not read severity for '{alarm_type}' from DB, using default '{default_severity}': {exc}")
        return default_severity

    def _get_alarm_channels(self, session: Session, alarm_type: str):
        """
        Return (telegram_enabled, email_enabled) for an alarm type from alarm_severity_config.
        The DB values (set via the admin UI) are the authoritative source.
        Falls back to the static notify_on lists in config.yml when the row is
        missing or the query fails.
        """
        try:
            row = session.execute(
                text("SELECT telegram_enabled, email_enabled FROM alarm_severity_config WHERE alarm_type = :t"),
                {"t": alarm_type}
            ).fetchone()
            if row is not None:
                return bool(row[0]), bool(row[1])
        except Exception as exc:
            self.logger.warning(f"Could not read notification channels for '{alarm_type}' from DB, falling back to config: {exc}")
        # Fallback: use static notify_on lists from config.yml
        return (
            alarm_type in self.config.telegram.notify_on,
            alarm_type in self.config.email.notify_on
        )

    def _get_alarm_email_recipients(self, session: Session, alarm_type: str) -> Optional[list]:
        """
        Return a filtered list of email addresses for this alarm type based on
        per-user settings stored in alarm_user_email_config joined with users.
        Returns None when the table does not exist or has no rows for this alarm
        type (caller should fall back to the global to_addresses list).
        """
        try:
            rows = session.execute(
                text(
                    "SELECT u.email FROM alarm_user_email_config auc "
                    "JOIN users u ON u.id = auc.user_id "
                    "WHERE auc.alarm_type = :t AND auc.email_enabled = 1 "
                    "AND u.is_active = 1 AND u.email IS NOT NULL AND u.email != ''"
                ),
                {"t": alarm_type}
            ).fetchall()
            # Only return a filtered list if at least one row exists for this alarm type;
            # if the table is empty for this alarm type we fall back to global list.
            all_rows = session.execute(
                text("SELECT COUNT(*) FROM alarm_user_email_config WHERE alarm_type = :t"),
                {"t": alarm_type}
            ).fetchone()
            if all_rows and all_rows[0] > 0:
                return [r[0] for r in rows if r[0]]
        except Exception as exc:
            self.logger.debug(f"alarm_user_email_config not available, using global to_addresses: {exc}")
        return None

    def _log_email(self, session: Session, subject: str, recipients: list,
                   alarm_type: str, mail_type: str, status: str, error_msg: str = None) -> None:
        """
        Insert a row into email_log if the table exists.
        Silently ignores errors (table may not exist on older deployments).
        """
        try:
            recipients_str = ', '.join(recipients) if recipients else ''
            session.execute(
                text(
                    "IF OBJECT_ID('dbo.email_log','U') IS NOT NULL "
                    "INSERT INTO email_log (sent_at, subject, recipients, alarm_type, mail_type, status, error_msg) "
                    "VALUES (GETDATE(), :s, :r, :at, :mt, :st, :em)"
                ),
                {"s": subject[:500] if subject else None,
                 "r": recipients_str[:2000] if recipients_str else None,
                 "at": alarm_type[:100] if alarm_type else None,
                 "mt": mail_type[:100] if mail_type else None,
                 "st": status[:20],
                 "em": error_msg[:1000] if error_msg else None}
            )
            session.commit()
        except Exception as exc:
            self.logger.debug(f"Could not log email send: {exc}")

    def _send_notifications(
        self,
        device: SNMPDevice,
        alarm_type: str,
        severity: str,
        message: str,
        port_number: Optional[int] = None,
        port_name: Optional[str] = None,
        session: Optional[Session] = None,
        extra_data: Optional[dict] = None
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
            session: DB session used to read per-alarm channel flags from
                     alarm_severity_config.  When provided the DB values take
                     precedence over the static notify_on lists in config.yml.
        """
        # Severity zaten büyük harf olarak gelmeli
        severity_upper = severity.upper() if severity else "MEDIUM"
        
        # Resolve per-alarm channel flags: prefer DB (admin-UI configurable),
        # fall back to static config.yml notify_on lists.
        if session is not None:
            telegram_channel_on, email_channel_on = self._get_alarm_channels(session, alarm_type)
        else:
            telegram_channel_on = alarm_type in self.config.telegram.notify_on
            email_channel_on = alarm_type in self.config.email.notify_on

        # Check if this alarm type should trigger notifications
        telegram_notify = (
            self.telegram_service 
            and self.config.telegram.enabled 
            and telegram_channel_on
        )
        
        email_notify = (
            self.email_service 
            and self.config.email.enabled 
            and email_channel_on
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
            # Resolve per-user recipient list for this alarm type
            email_recipients = None
            if session is not None:
                email_recipients = self._get_alarm_email_recipients(session, alarm_type)
            effective_recipients = email_recipients if email_recipients is not None else self.email_service.to_addresses
            subject_map = {
                "port_down": f"[HIGH] Port Kapandı - {device.name}",
                "device_unreachable": f"[CRITICAL] Device Unreachable - {device.name}",
                "mac_moved": "CHAMADA Network Alert – MAC Hareketi",
            }
            email_subject = subject_map.get(alarm_type, f"CHAMADA Network Alert - {alarm_type}")
            try:
                if alarm_type == "port_down" and port_number:
                    self.email_service.send_port_down(
                        device.name, device.ip_address, port_number, port_name or "",
                        recipients=email_recipients
                    )
                elif alarm_type == "device_unreachable":
                    self.email_service.send_device_unreachable(
                        device.name, device.ip_address,
                        recipients=email_recipients
                    )
                elif alarm_type == "mac_moved" and extra_data:
                    self.email_service.send_mac_moved(
                        severity=severity_upper,
                        message=message,
                        recipients=email_recipients,
                        **extra_data
                    )
                else:
                    self.email_service.send_alarm(
                        device.name, device.ip_address, alarm_type, severity_upper, message,
                        recipients=email_recipients
                    )
                if session is not None:
                    self._log_email(session, email_subject, effective_recipients,
                                    alarm_type, "alarm", "sent")
            except Exception as e:
                self.logger.error(f"Failed to send email notification: {e}")
                if session is not None:
                    self._log_email(session, email_subject, effective_recipients,
                                    alarm_type, "alarm", "failed", str(e))
    
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
            # Only raise the alarm after the device has failed at least
            # `unreachable_threshold` consecutive polls.  This prevents
            # instant false-positive alarms for newly-added switches that
            # haven't been configured yet.
            threshold = self.config.alarms.unreachable_threshold
            if device.poll_failures < threshold:
                self.logger.debug(
                    f"Device {device.name} unreachable "
                    f"(failures={device.poll_failures}/{threshold}, waiting for threshold)"
                )
                return
            
            # Device is unreachable - create alarm
            severity = self._get_alarm_severity(session, alarm_type, "CRITICAL")
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                alarm_type,
                severity,
                f"Device {device.name} is unreachable",
                f"Device {device.name} is not responding to SNMP requests."
            )
            
            # Send notification if it's a new alarm and debounce allows
            if is_new and self._should_notify(alarm_key):
                self._send_notifications(
                    device, 
                    alarm_type, 
                    severity,
                    f"Device is not responding to SNMP requests.",
                    session=session
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
    
    @staticmethod
    def _port_context_suffix(vlan_id: Optional[int], port_alias: Optional[str]) -> str:
        """Build a human-readable context string for alarm messages.

        Returns a string like ". VLAN 1500, Mevcut Bağlantı DRGT." (with a leading
        period-space) so it can be appended directly to any existing message.  Returns
        an empty string when neither piece of information is available.
        """
        parts = []
        if vlan_id:
            parts.append(f"VLAN {vlan_id}")
        if port_alias:
            parts.append(f"Mevcut Bağlantı {port_alias}")
        return (". " + ", ".join(parts) + ".") if parts else ""

    def _get_mevcut_label(
        self,
        session: Session,
        device_id: int,
        port_number: int,
        port_alias: Optional[str]
    ) -> Optional[str]:
        """Return enriched 'Mevcut Bağlantı' label using Device Import info when available.

        Looks up the current MAC address(es) on the port from port_snapshot, then
        queries mac_device_registry for a matching entry.  Returns
        '{ip} {name} olarak kayıtlı' when found, otherwise falls back to port_alias.
        Both the single mac_address column and the mac_addresses JSON column are
        checked so hub/multi-MAC ports are also covered.
        """
        import json as _json
        try:
            row = session.execute(
                text(
                    "SELECT TOP 1 mac_address, mac_addresses FROM port_snapshot "
                    "WHERE device_id = :did AND port_number = :port"
                ),
                {"did": device_id, "port": port_number}
            ).fetchone()
            if row:
                # Build candidate MAC list: primary MAC first, then hub MACs
                candidates = []
                if row[0]:
                    candidates.append(row[0])
                if row[1]:
                    try:
                        extra = _json.loads(row[1])
                        if isinstance(extra, list):
                            candidates.extend(m for m in extra if m and m not in candidates)
                    except Exception:
                        pass
                for mac in candidates:
                    reg = session.execute(
                        text(
                            "SELECT TOP 1 ip_address, device_name FROM mac_device_registry "
                            "WHERE mac_address = :mac"
                        ),
                        {"mac": mac}
                    ).fetchone()
                    if reg:
                        parts = [p for p in [reg[0], reg[1]] if p]
                        if parts:
                            return ' '.join(parts) + ' olarak kayıtlı'
        except Exception:
            pass
        return port_alias

    def check_port_status(
        self,
        session: Session,
        device: SNMPDevice,
        port_number: int,
        port_name: str,
        admin_status: PortStatus,
        oper_status: PortStatus,
        vlan_id: Optional[int] = None,
        port_alias: Optional[str] = None
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
            vlan_id: Access VLAN of the port (used for VLAN filtering)
            port_alias: ifAlias / user-configured port description
        """
        # Apply VLAN exclude list: suppress port_down/port_up for ports whose
        # access VLAN is in the excluded list (these VLANs generate too many alarms).
        # Ports with no VLAN assigned (vlan_id is None) are NOT suppressed.
        vlan_exclude = self.config.alarms.vlan_exclude
        if vlan_exclude and vlan_id is not None and vlan_id in vlan_exclude:
            return

        # Apply per-device monitored_ports filter.
        # If the device has a non-empty monitored_ports list in config, only
        # ports in that list will produce port_down/port_up alarms.
        # Ports NOT in the list still have their state tracked internally
        # (so we don't miss transitions) but never generate alarms or DB records.
        device_monitored = self._monitored_ports.get(device.name)
        if device_monitored and port_number not in device_monitored:
            # Still track state to avoid spurious alarms when/if port is later
            # added to the monitored list.
            self._port_states[(device.id, port_number)] = oper_status
            return

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
        # Refresh core-port cache and check whether this port is a core uplink.
        self._load_core_ports(session)
        core_switch_name = self._core_ports.get((device.id, port_number))

        if oper_status == PortStatus.DOWN and admin_status == PortStatus.UP:
            # Port went down (but is administratively up) - create alarm.
            _mevcut = self._get_mevcut_label(session, device.id, port_number, port_alias)
            _ctx = self._port_context_suffix(vlan_id, _mevcut)

            # Core uplink ports get a dedicated alarm type with a descriptive message.
            if core_switch_name:
                core_severity = self._get_alarm_severity(session, "core_link_down", "CRITICAL")
                core_msg = (
                    f"Core bağlantısı gitti: {core_switch_name} — "
                    f"{device.name} Port {port_number} ({port_name}) kapandı{_ctx}"
                )
                alarm, is_new = self.db_manager.get_or_create_alarm(
                    session,
                    device,
                    "core_link_down",
                    core_severity,
                    f"Core bağlantısı gitti: {core_switch_name}",
                    core_msg,
                    port_number=port_number
                )
                alarm_key = f"{device.id}_port_{port_number}_core_link_down"
                if self._should_notify(alarm_key):
                    self._send_notifications(
                        device,
                        "core_link_down",
                        core_severity,
                        core_msg,
                        port_number=port_number,
                        port_name=port_name,
                        session=session
                    )
                    alarm.notification_sent = True
                    alarm.last_notification_sent = datetime.utcnow()
                    self._mark_notified(alarm_key)
                    self.logger.warning(
                        f"CORE LINK DOWN: {device.name} port {port_number} → {core_switch_name}"
                    )

            # Always also create a regular port_down alarm so the port shows as
            # down in the UI regardless of the core-port designation.
            port_down_severity = self._get_alarm_severity(session, "port_down", "HIGH")
            port_down_detail = (
                f"{device.name} Port {port_number} ({port_name}) bağlantısı kesildi{_ctx}"
            )
            port_down_notif = (
                f"Port {port_number} ({port_name}) bağlantısı kesildi{_ctx}"
            )
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                "port_down",
                port_down_severity,
                f"Port {port_number} kapandı",
                port_down_detail,
                port_number=port_number
            )
            
            alarm_key = f"{device.id}_port_{port_number}_port_down"
            
            # Send notification if debounce allows
            if self._should_notify(alarm_key):
                self._send_notifications(
                    device, 
                    "port_down", 
                    port_down_severity,
                    port_down_notif,
                    port_number=port_number,
                    port_name=port_name,
                    session=session
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

            # Resolve core_link_down alarms if port is a core uplink
            if core_switch_name:
                core_alarms = session.query(Alarm).filter(
                    Alarm.device_id == device.id,
                    Alarm.alarm_type == "core_link_down",
                    Alarm.port_number == port_number,
                    Alarm.status == AlarmStatus.ACTIVE
                ).all()
                for alarm in core_alarms:
                    self.db_manager.resolve_alarm(
                        session, alarm,
                        f"Core bağlantısı geldi: {core_switch_name}"
                    )
                    self.logger.info(
                        f"CORE LINK RESTORED: {device.name} port {port_number} → {core_switch_name}"
                    )
            
            # Optionally send "port up" notification
            alarm_key = f"{device.id}_port_{port_number}_port_up"
            telegram_up, email_up = self._get_alarm_channels(session, "port_up")
            if telegram_up or email_up:
                if self._should_notify(alarm_key):
                    # Default is MEDIUM (matches alarm_severity_config default); the
                    # previous hardcoded value "INFO" was not a valid severity enum.
                    port_up_severity = self._get_alarm_severity(session, "port_up", "MEDIUM")
                    self._send_notifications(
                        device, 
                        "port_up", 
                        port_up_severity,
                        f"Port {port_number} ({port_name}) is now up.",
                        port_number=port_number,
                        port_name=port_name,
                        session=session
                    )
                    self._mark_notified(alarm_key)
    
    def check_temperature(
        self,
        session: Session,
        device: SNMPDevice,
        temperature_c: Optional[float],
        threshold: float = 70.0
    ) -> None:
        """
        Check device temperature and create/resolve alarms.
        An alarm is raised when temperature_c >= threshold (default 70 °C).
        The alarm is auto-resolved when the temperature drops below threshold.
        """
        if temperature_c is None:
            return

        alarm_type = "high_temperature"
        alarm_key  = f"{device.id}_{alarm_type}"

        if temperature_c >= threshold:
            severity = self._get_alarm_severity(session, alarm_type, "HIGH")
            message  = (
                f"{device.name} sıcaklığı kritik seviyeye ulaştı: "
                f"{temperature_c:.1f}°C (eşik: {threshold:.0f}°C)"
            )
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                alarm_type,
                severity,
                f"Yüksek sıcaklık: {temperature_c:.1f}°C",
                message,
            )
            if is_new and self._should_notify(alarm_key):
                self._send_notifications(
                    device, alarm_type, severity, message, session=session
                )
                alarm.notification_sent        = True
                alarm.last_notification_sent   = datetime.utcnow()
                self._mark_notified(alarm_key)
                self.logger.warning(
                    f"HIGH TEMPERATURE: {device.name} → {temperature_c:.1f}°C"
                )
        else:
            # Temperature back to normal — resolve active alarms
            active = session.query(Alarm).filter(
                Alarm.device_id  == device.id,
                Alarm.alarm_type == alarm_type,
                Alarm.status     == AlarmStatus.ACTIVE,
            ).all()
            for a in active:
                self.db_manager.resolve_alarm(
                    session, a,
                    f"Sıcaklık normale döndü: {temperature_c:.1f}°C"
                )
                self.logger.info(
                    f"Temperature alarm resolved for {device.name} ({temperature_c:.1f}°C)"
                )

    def check_fan_status(
        self,
        session: Session,
        device: SNMPDevice,
        fan_status: Optional[str]
    ) -> None:
        """
        Check device fan status and create/resolve alarms.
        Alarm is raised when fan_status is 'CRITICAL' or 'FAIL'.
        Alarm is resolved when fan_status is 'OK'.
        """
        if fan_status is None:
            return

        alarm_type = "fan_failure"
        alarm_key  = f"{device.id}_{alarm_type}"

        fan_upper = fan_status.upper().strip()
        is_failed = fan_upper in ("CRITICAL", "FAIL", "FAILED", "FAILURE")
        is_ok     = fan_upper in ("OK", "NORMAL", "GOOD")

        if is_failed:
            severity = self._get_alarm_severity(session, alarm_type, "CRITICAL")
            message  = (
                f"{device.name} fan arızası tespit edildi "
                f"(durum: {fan_status})"
            )
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                alarm_type,
                severity,
                f"Fan arızası: {fan_status}",
                message,
            )
            if is_new and self._should_notify(alarm_key):
                self._send_notifications(
                    device, alarm_type, severity, message, session=session
                )
                alarm.notification_sent       = True
                alarm.last_notification_sent  = datetime.utcnow()
                self._mark_notified(alarm_key)
                self.logger.warning(
                    f"FAN FAILURE: {device.name} → {fan_status}"
                )
        elif is_ok:
            active = session.query(Alarm).filter(
                Alarm.device_id  == device.id,
                Alarm.alarm_type == alarm_type,
                Alarm.status     == AlarmStatus.ACTIVE,
            ).all()
            for a in active:
                self.db_manager.resolve_alarm(
                    session, a, "Fan durumu normale döndü"
                )
                self.logger.info(
                    f"Fan alarm resolved for {device.name}"
                )

    def check_cpu_usage(
        self,
        session: Session,
        device: SNMPDevice,
        cpu_1min: Optional[int],
        threshold: int = 30
    ) -> None:
        """
        Check device CPU usage and create/resolve alarms.
        An alarm is raised when cpu_1min >= threshold (default 30 %).
        The alarm is auto-resolved when CPU drops below threshold.
        """
        if cpu_1min is None:
            return

        alarm_type = "high_cpu"
        alarm_key  = f"{device.id}_{alarm_type}"

        if cpu_1min >= threshold:
            severity = self._get_alarm_severity(session, alarm_type, "HIGH")
            message  = (
                f"{device.name} işlemci kullanımı yüksek: "
                f"%{cpu_1min} (eşik: %{threshold})"
            )
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                alarm_type,
                severity,
                f"Yüksek CPU: %{cpu_1min}",
                message,
            )
            if is_new and self._should_notify(alarm_key):
                self._send_notifications(
                    device, alarm_type, severity, message, session=session
                )
                alarm.notification_sent       = True
                alarm.last_notification_sent  = datetime.utcnow()
                self._mark_notified(alarm_key)
                self.logger.warning(
                    f"HIGH CPU: {device.name} → %{cpu_1min}"
                )
        else:
            active = session.query(Alarm).filter(
                Alarm.device_id  == device.id,
                Alarm.alarm_type == alarm_type,
                Alarm.status     == AlarmStatus.ACTIVE,
            ).all()
            for a in active:
                self.db_manager.resolve_alarm(
                    session, a,
                    f"CPU kullanımı normale döndü: %{cpu_1min}"
                )
                self.logger.info(
                    f"CPU alarm resolved for {device.name} (%{cpu_1min})"
                )

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

    def _load_core_ports(self, session: Session) -> None:
        """Refresh the in-memory core-ports cache from snmp_core_ports table (TTL=60s)."""
        now = datetime.utcnow()
        if (self._core_ports_loaded_at is not None and
                (now - self._core_ports_loaded_at).total_seconds() < 60):
            return
        try:
            rows = session.execute(
                text("SELECT device_id, port_number, core_switch_name FROM snmp_core_ports")
            ).fetchall()
            self._core_ports = {(r[0], r[1]): r[2] for r in rows}
            self._core_ports_loaded_at = now
        except Exception as exc:
            # Table may not exist yet (migration pending) — silently skip.
            self.logger.debug(f"Could not load snmp_core_ports (table may not exist yet): {exc}")