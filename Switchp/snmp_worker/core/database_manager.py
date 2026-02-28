"""
Database manager for SNMP Worker.
Handles database connections and operations.
"""

from typing import Optional, List, Union
from datetime import datetime
from sqlalchemy import create_engine, and_, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
import logging

from models.database import (
    Base, SNMPDevice, DevicePollingData, PortStatusData,
    Alarm, AlarmHistory, DeviceStatus, PortStatus, AlarmStatus, AlarmSeverity
)
from config.config_loader import Config


class DatabaseManager:
    """Database manager for SNMP Worker."""
    
    def __init__(self, config: Config):
        """
        Initialize database manager.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger('snmp_worker.db')
        
        # Create engine
        db_url = config.get_database_url()
        self.engine = create_engine(
            db_url,
            poolclass=QueuePool,
            pool_size=config.database.pool_size,
            max_overflow=config.database.max_overflow,
            pool_pre_ping=True,
            echo=False
        )
        
        # Create session factory
        self.Session = sessionmaker(bind=self.engine)
        
        self.logger.info("Database manager initialized")
    
    @contextmanager
    def session_scope(self):
        """
        Provide a transactional scope around a series of operations.
        
        Yields:
            Database session
        """
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            session.close()
    
    def get_or_create_device(
        self,
        session: Session,
        name: str,
        ip_address: str,
        vendor: str,
        model: str,
        **kwargs
    ) -> SNMPDevice:
        """
        Get existing device or create new one.
        
        Args:
            session: Database session
            name: Device name
            ip_address: Device IP
            vendor: Vendor name
            model: Model name
            **kwargs: Additional device attributes
            
        Returns:
            SNMPDevice instance
        """
        # First, try to find device by IP address
        device = session.query(SNMPDevice).filter_by(ip_address=ip_address).first()
        
        if device:
            if device.name != name:
                self.logger.info(f"Updating device name from '{device.name}' to '{name}' for IP {ip_address}")
            device.name = name
            device.vendor = vendor
            device.model = model
            for key, value in kwargs.items():
                if hasattr(device, key):
                    setattr(device, key, value)
        else:
            device_by_name = session.query(SNMPDevice).filter_by(name=name).first()
            if device_by_name:
                self.logger.info(f"Updating device IP from '{device_by_name.ip_address}' to '{ip_address}' for {name}")
                device = device_by_name
                device.ip_address = ip_address
                device.vendor = vendor
                device.model = model
                for key, value in kwargs.items():
                    if hasattr(device, key):
                        setattr(device, key, value)
            else:
                device = SNMPDevice(
                    name=name,
                    ip_address=ip_address,
                    vendor=vendor,
                    model=model,
                    **kwargs
                )
                session.add(device)
                session.flush()
                self.logger.info(f"Created new device: {name} ({ip_address})")
        
        return device
    
    def update_device_status(
        self,
        session: Session,
        device: SNMPDevice,
        status: DeviceStatus,
        system_description: Optional[str] = None,
        system_uptime: Optional[int] = None,
        total_ports: Optional[int] = None
    ) -> None:
        """
        Update device status and information.
        
        Args:
            session: Database session
            device: Device to update
            status: Device status
            system_description: System description
            system_uptime: System uptime in seconds
            total_ports: Total number of ports
        """
        device.status = status
        device.last_poll_time = datetime.utcnow()
        
        if status in [DeviceStatus.ONLINE]:
            device.last_successful_poll = datetime.utcnow()
            device.poll_failures = 0
        else:
            device.poll_failures += 1
        
        if system_description:
            device.system_description = system_description
        if system_uptime is not None:
            device.system_uptime = system_uptime
        if total_ports is not None:
            device.total_ports = total_ports
        
        device.updated_at = datetime.utcnow()
    
    def save_polling_data(
        self,
        session: Session,
        device: SNMPDevice,
        success: bool,
        poll_duration_ms: float,
        error_message: Optional[str] = None,
        **metrics
    ) -> DevicePollingData:
        """
        Save polling data.
        
        Args:
            session: Database session
            device: Device
            success: Whether polling was successful
            poll_duration_ms: Polling duration in milliseconds
            error_message: Error message if failed
            **metrics: Additional metrics
            
        Returns:
            DevicePollingData instance
        """
        polling_data = DevicePollingData(
            device_id=device.id,
            success=success,
            poll_duration_ms=poll_duration_ms,
            error_message=error_message,
            **metrics
        )
        session.add(polling_data)
        return polling_data
    
    def save_port_status(
        self,
        session: Session,
        device: SNMPDevice,
        port_number: int,
        admin_status: PortStatus,
        oper_status: PortStatus,
        **port_data
    ) -> PortStatusData:
        """
        Save or update port status.
        
        Args:
            session: Database session
            device: Device
            port_number: Port number
            admin_status: Administrative status
            oper_status: Operational status
            **port_data: Additional port data
            
        Returns:
            PortStatusData instance
        """
        existing_port = session.query(PortStatusData).filter_by(
            device_id=device.id,
            port_number=port_number
        ).order_by(PortStatusData.poll_timestamp.desc()).first()
        
        port_status = PortStatusData(
            device_id=device.id,
            port_number=port_number,
            admin_status=admin_status,
            oper_status=oper_status,
            poll_timestamp=datetime.utcnow(),
            **port_data
        )
        
        if existing_port:
            port_status.first_seen = existing_port.first_seen
        
        session.add(port_status)
        return port_status
    
    def get_or_create_alarm(
        self,
        session: Session,
        device: SNMPDevice,
        alarm_type: str,
        severity: Union[AlarmSeverity, str],
        title: str,
        message: str,
        port_number: Optional[int] = None,
        mac_address: Optional[str] = None,
        from_port: Optional[int] = None,
        to_port: Optional[int] = None,
        old_vlan_id: Optional[int] = None,
        new_vlan_id: Optional[int] = None,
        skip_whitelist: bool = False
    ) -> tuple[Alarm, bool]:
        """
        Get existing active alarm or create new one with uniqueness checking.
        
        Alarm uniqueness is determined by:
        - device_name
        - port_number
        - mac_address
        - from_port
        - to_port
        
        If alarm is whitelisted (acknowledged_port_mac), no alarm is created
        (unless skip_whitelist=True).
        
        Args:
            session: Database session
            device: Device
            alarm_type: Type of alarm
            severity: Alarm severity (AlarmSeverity enum or string)
            title: Alarm title
            message: Alarm message
            port_number: Port number (for port-specific alarms)
            mac_address: MAC address involved in alarm
            from_port: Source port for MAC moved alarms
            to_port: Destination port for MAC moved alarms
            old_vlan_id: Old VLAN ID (for VLAN change tracking)
            new_vlan_id: New VLAN ID (for VLAN change tracking)
            skip_whitelist: Skip whitelist check (for config mismatch alarms)
            
        Returns:
            Tuple of (Alarm instance or None, is_new)
        """
        # Normalize severity to AlarmSeverity enum
        if isinstance(severity, str):
            severity_upper = severity.upper()
            
            if severity_upper == "CRITICAL":
                severity = AlarmSeverity.CRITICAL
            elif severity_upper == "HIGH":
                severity = AlarmSeverity.HIGH
            elif severity_upper == "MEDIUM":
                severity = AlarmSeverity.MEDIUM
            elif severity_upper == "LOW":
                severity = AlarmSeverity.LOW
            elif severity_upper == "INFO":
                severity = AlarmSeverity.INFO
            else:
                severity = AlarmSeverity.MEDIUM
        
        elif not isinstance(severity, AlarmSeverity):
            severity = AlarmSeverity.MEDIUM
        
        # Check whitelist for MAC+Port alarms (unless skip_whitelist is True)
        # Configuration mismatch alarms should skip whitelist because:
        # - Whitelist means "this MAC on this port is expected/normal"
        # - Config mismatch means "user expects DIFFERENT MAC than what's there"
        # - These two situations are contradictory
        if mac_address and port_number and not skip_whitelist:
            whitelisted = self._check_whitelist(session, device.name, port_number, mac_address)
            if whitelisted:
                self.logger.info(
                    f"Alarm suppressed (whitelisted): {device.name} port {port_number} "
                    f"MAC {mac_address}"
                )
                return None, False
        elif mac_address and port_number and skip_whitelist:
            self.logger.warning(
                f"⚠️ WHITELIST ATLATILDI (skip_whitelist=True): {device.name} port {port_number} "
                f"MAC {mac_address} - Config mismatch alarm oluşturuluyor"
            )
        
        # Create alarm fingerprint for uniqueness check
        fingerprint = self._create_alarm_fingerprint(
            device.name, port_number, mac_address, from_port, to_port, alarm_type
        )
        
        # Check for existing active alarm with same fingerprint
        existing_alarm = session.query(Alarm).filter(
            Alarm.device_id == device.id,
            Alarm.alarm_type == alarm_type,
            Alarm.status == AlarmStatus.ACTIVE,
            Alarm.alarm_fingerprint == fingerprint
        ).first()
        
        if existing_alarm:
            # Update existing alarm - increment counter and update last_occurrence
            existing_alarm.occurrence_count += 1
            existing_alarm.last_occurrence = datetime.utcnow()
            existing_alarm.updated_at = datetime.utcnow()
            
            self.logger.info(
                f"Updated existing alarm #{existing_alarm.id}: "
                f"count={existing_alarm.occurrence_count}"
            )
            return existing_alarm, False
        
        # Create new alarm
        alarm = Alarm(
            device_id=device.id,
            alarm_type=alarm_type,
            severity=severity,
            title=title,
            message=message,
            port_number=port_number,
            mac_address=mac_address,
            from_port=from_port,
            to_port=to_port,
            old_vlan_id=old_vlan_id,
            new_vlan_id=new_vlan_id,
            alarm_fingerprint=fingerprint,
            status=AlarmStatus.ACTIVE,
            occurrence_count=1
        )
        session.add(alarm)
        session.flush()
        
        self.logger.warning("=" * 80)
        self.logger.warning(f"🚨 YENİ ALARM OLUŞTURULDU!")
        self.logger.warning(f"   Alarm ID: {alarm.id}")
        self.logger.warning(f"   Device: {device.name}")
        self.logger.warning(f"   Type: {alarm_type}")
        self.logger.warning(f"   Severity: {severity}")
        self.logger.warning(f"   Port: {port_number}")
        self.logger.warning(f"   MAC: {mac_address}")
        self.logger.warning(f"   Fingerprint: {fingerprint}")
        self.logger.warning(f"   skip_whitelist was: {skip_whitelist}")
        self.logger.warning("=" * 80)
        
        # Add to history
        history = AlarmHistory(
            alarm_id=alarm.id,
            old_status=None,
            new_status=AlarmStatus.ACTIVE,
            change_reason="Alarm created",
            change_message=message
        )
        session.add(history)
        
        self.logger.info(f"New alarm created: ID={alarm.id}, fingerprint={fingerprint}")
        return alarm, True
    
    def _create_alarm_fingerprint(
        self,
        device_name: str,
        port_number: Optional[int],
        mac_address: Optional[str],
        from_port: Optional[int],
        to_port: Optional[int],
        alarm_type: str
    ) -> str:
        """
        Create unique fingerprint for alarm.
        
        Fingerprint format: device_name|port|mac|from_port|to_port|type
        MAC addresses are normalized to uppercase for consistency.
        """
        parts = [
            device_name or "",
            str(port_number) if port_number else "",
            mac_address.upper() if mac_address else "",
            str(from_port) if from_port else "",
            str(to_port) if to_port else "",
            alarm_type or ""
        ]
        return "|".join(parts)
    
    def _check_whitelist(
        self,
        session: Session,
        device_name: str,
        port_number: int,
        mac_address: str
    ) -> bool:
        """
        Check if device+port+mac combination is whitelisted.
        
        Returns True if whitelisted (alarm should be suppressed).
        """
        try:
            # Normalize MAC address to uppercase for consistency
            mac_address = mac_address.upper() if mac_address else ""
            
            # Use raw SQL since acknowledged_port_mac table may not have SQLAlchemy model yet
            query = text("""
                SELECT COUNT(*) as count
                FROM acknowledged_port_mac
                WHERE device_name = :device_name
                AND port_number = :port_number
                AND mac_address = :mac_address
            """)
            result = session.execute(
                query,
                {
                    'device_name': device_name,
                    'port_number': port_number,
                    'mac_address': mac_address
                }
            ).fetchone()
            
            is_whitelisted = result[0] > 0 if result else False
            
            if is_whitelisted:
                self.logger.debug(
                    f"Whitelist match found: {device_name} port {port_number} MAC {mac_address}"
                )
            
            return is_whitelisted
        except Exception as e:
            self.logger.warning(f"Whitelist check failed: {e}")
            return False
    
    def resolve_alarm(
        self,
        session: Session,
        alarm: Alarm,
        reason: str = "Condition cleared"
    ) -> None:
        """
        Resolve an alarm.
        
        Args:
            session: Database session
            alarm: Alarm to resolve
            reason: Reason for resolution
        """
        if alarm.status != AlarmStatus.RESOLVED:
            old_status = alarm.status
            alarm.status = AlarmStatus.RESOLVED
            alarm.resolved_at = datetime.utcnow()
            
            # Add to history
            history = AlarmHistory(
                alarm_id=alarm.id,
                old_status=old_status,
                new_status=AlarmStatus.RESOLVED,
                change_reason=reason
            )
            session.add(history)
            self.logger.info(f"Resolved alarm: {alarm.alarm_type} for device ID {alarm.device_id}")
    
    def get_active_alarms(
        self,
        session: Session,
        device: Optional[SNMPDevice] = None
    ) -> List[Alarm]:
        """
        Get active alarms.
        
        Args:
            session: Database session
            device: Optional device filter
            
        Returns:
            List of active alarms
        """
        query = session.query(Alarm).filter(Alarm.status == AlarmStatus.ACTIVE)
        
        if device:
            query = query.filter(Alarm.device_id == device.id)
        
        return query.all()
    
    def cleanup_old_data(
        self,
        session: Session,
        days: int = 30
    ) -> None:
        """
        Clean up old polling data.
        
        Args:
            session: Database session
            days: Number of days to keep
        """
        from datetime import timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Delete old polling data
        session.query(DevicePollingData).filter(
            DevicePollingData.poll_timestamp < cutoff_date
        ).delete()
    
    def update_port_operational_status(
        self,
        session: Session,
        device: SNMPDevice,
        port_number: int,
        oper_status: str
    ) -> None:
        """
        Update port operational status in legacy ports table without clearing connection data.
        
        This preserves connection information (device, ip, mac, connected_to) when port goes down.
        The port status is tracked separately so:
        - UI can show port as red (down) while keeping connection data
        - When port comes up, connection data can be compared
        - If data changed -> alarm, if same -> no alarm
        
        Args:
            session: Database session
            device: SNMP Device
            port_number: Port number
            oper_status: Operational status ('up' or 'down')
            
        Note: Uses raw SQL to update legacy ports table.
        """
        try:
            # Update only the operational status, preserve all connection data
            session.execute(
                text("""
                UPDATE ports p
                JOIN switches s ON p.switch_id = s.id
                SET p.oper_status = :oper_status,
                    p.last_status_update = NOW()
                WHERE s.name = :device_name 
                AND p.port_no = :port_number
                """),
                {
                    "oper_status": oper_status,
                    "device_name": device.name,
                    "port_number": port_number
                }
            )
            session.flush()
            
            self.logger.debug(
                f"Updated port {port_number} on {device.name} to oper_status={oper_status}"
            )
        except Exception as e:
            self.logger.warning(
                f"Could not update port operational status: {e}"
            )