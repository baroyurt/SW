"""
Database models for SNMP Worker.
Uses SQLAlchemy ORM for PostgreSQL.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, 
    ForeignKey, Enum, Float, Index, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum
import pytz

Base = declarative_base()

# Get Athens timezone (UTC+2)
try:
    ATHENS_TZ = pytz.timezone('Europe/Athens')
except:
    ATHENS_TZ = pytz.UTC  # Fallback to UTC if timezone not available

def get_current_time():
    """Get current time in configured timezone (Athens UTC+2)."""
    return datetime.now(ATHENS_TZ)


class DeviceStatus(str, enum.Enum):
    """Device status enumeration."""
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    UNREACHABLE = "UNREACHABLE"
    ERROR = "ERROR"


class PortStatus(str, enum.Enum):
    """Port status enumeration."""
    UP = "up"
    DOWN = "down"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class AlarmSeverity(str, enum.Enum):
    """Alarm severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlarmStatus(str, enum.Enum):
    """Alarm status."""
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class SNMPDevice(Base):
    """
    SNMP-enabled network devices.
    Extended version of the original 'switches' table for SNMP polling.
    """
    __tablename__ = "snmp_devices"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    ip_address = Column(String(50), nullable=False)
    vendor = Column(String(50), nullable=False)
    model = Column(String(50), nullable=False)
    
    # SNMP Configuration
    snmp_version = Column(String(10), nullable=False, default="2c")
    snmp_community = Column(String(100))  # For v2c
    snmp_v3_username = Column(String(100))
    snmp_v3_auth_protocol = Column(String(20))
    snmp_v3_auth_password = Column(String(200))
    snmp_v3_priv_protocol = Column(String(20))
    snmp_v3_priv_password = Column(String(200))
    snmp_engine_id = Column(String(100))  # SNMPv3 Engine ID (hex string)
    
    # Device Info
    status = Column(Enum(DeviceStatus), default=DeviceStatus.OFFLINE, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    total_ports = Column(Integer)
    system_description = Column(Text)
    system_uptime = Column(Integer)  # in seconds
    
    # Polling Info
    last_poll_time = Column(DateTime)
    last_successful_poll = Column(DateTime)
    poll_failures = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=get_current_time, nullable=False)
    updated_at = Column(DateTime, default=get_current_time, onupdate=get_current_time, nullable=False)
    
    # Relationships
    polling_data = relationship("DevicePollingData", back_populates="device", cascade="all, delete-orphan")
    port_data = relationship("PortStatusData", back_populates="device", cascade="all, delete-orphan")
    alarms = relationship("Alarm", back_populates="device", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_snmp_devices_ip', 'ip_address'),
        Index('idx_snmp_devices_status', 'status'),
        Index('idx_snmp_devices_enabled', 'enabled'),
    )
    
    def __repr__(self) -> str:
        return f"<SNMPDevice(id={self.id}, name='{self.name}', ip='{self.ip_address}', status='{self.status}')>"


class DevicePollingData(Base):
    """
    Historical polling data for devices.
    Stores general device metrics over time.
    """
    __tablename__ = "device_polling_data"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False)
    
    # Polling metrics
    poll_timestamp = Column(DateTime, default=get_current_time, nullable=False)
    poll_duration_ms = Column(Float)  # Time taken to poll
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text)
    
    # Device metrics
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    temperature = Column(Float)
    uptime_seconds = Column(Integer)
    
    # Relationships
    device = relationship("SNMPDevice", back_populates="polling_data")
    
    # Indexes
    __table_args__ = (
        Index('idx_polling_device_time', 'device_id', 'poll_timestamp'),
        Index('idx_polling_timestamp', 'poll_timestamp'),
    )
    
    def __repr__(self) -> str:
        return f"<DevicePollingData(id={self.id}, device_id={self.device_id}, timestamp={self.poll_timestamp})>"


class PortStatusData(Base):
    """
    Port status and configuration data.
    Stores current state and historical changes.
    """
    __tablename__ = "port_status_data"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False)
    
    # Port identification
    port_number = Column(Integer, nullable=False)
    port_name = Column(String(100))
    port_alias = Column(String(255))  # ifAlias - user-configured description
    port_description = Column(Text)
    
    # Port status
    admin_status = Column(Enum(PortStatus), nullable=False)  # Configured state
    oper_status = Column(Enum(PortStatus), nullable=False)  # Actual state
    last_change = Column(DateTime)
    
    # Port configuration
    port_type = Column(String(100))  # e.g., "ethernetCsmacd"
    port_speed = Column(Integer)  # in bps
    port_mtu = Column(Integer)
    
    # VLAN information
    vlan_id = Column(Integer)
    vlan_name = Column(String(100))
    
    # Connected device info
    mac_address = Column(String(17))  # MAC address of connected device
    mac_addresses = Column(Text)  # Multiple MAC addresses (JSON format)
    
    # Statistics
    bytes_in = Column(Integer, default=0)
    bytes_out = Column(Integer, default=0)
    packets_in = Column(Integer, default=0)
    packets_out = Column(Integer, default=0)
    errors_in = Column(Integer, default=0)
    errors_out = Column(Integer, default=0)
    
    # Timestamps
    first_seen = Column(DateTime, default=get_current_time, nullable=False)
    last_seen = Column(DateTime, default=get_current_time, onupdate=get_current_time, nullable=False)
    poll_timestamp = Column(DateTime, default=get_current_time, nullable=False)
    
    # Relationships
    device = relationship("SNMPDevice", back_populates="port_data")
    
    # Indexes and constraints
    __table_args__ = (
        Index('idx_port_device_port', 'device_id', 'port_number'),
        Index('idx_port_status', 'oper_status'),
        Index('idx_port_mac', 'mac_address'),
        Index('idx_port_vlan', 'vlan_id'),
        UniqueConstraint('device_id', 'port_number', 'poll_timestamp', name='uq_device_port_timestamp'),
    )
    
    def __repr__(self) -> str:
        return f"<PortStatusData(id={self.id}, device_id={self.device_id}, port={self.port_number}, status={self.oper_status})>"


class Alarm(Base):
    """
    Active alarms for devices and ports.
    """
    __tablename__ = "alarms"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False)
    
    # Alarm details
    alarm_type = Column(String(50), nullable=False)  # e.g., "port_down", "device_unreachable"
    severity = Column(Enum(AlarmSeverity), nullable=False, default=AlarmSeverity.MEDIUM)
    status = Column(Enum(AlarmStatus), nullable=False, default=AlarmStatus.ACTIVE)
    
    # Related object (if applicable)
    port_number = Column(Integer)  # null if device-level alarm
    
    # Alarm content
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    details = Column(Text)  # Additional details (JSON format)
    
    # Port change tracking (for MAC moved alarms)
    mac_address = Column(String(17))  # MAC address involved in the alarm
    old_value = Column(Text)  # Old value (for change detection)
    new_value = Column(Text)  # New value (for change detection)
    from_port = Column(Integer)  # Source port (for MAC moved)
    to_port = Column(Integer)  # Destination port (for MAC moved)
    old_vlan_id = Column(Integer)  # Old VLAN ID (for VLAN change tracking)
    new_vlan_id = Column(Integer)  # New VLAN ID (for VLAN change tracking)
    
    # Alarm uniqueness fingerprint
    alarm_fingerprint = Column(String(255))  # Unique identifier to prevent duplicates
    
    # Acknowledgment tracking
    acknowledgment_type = Column(String(50))  # Type of acknowledgment (known_change, silenced, resolved)
    silence_until = Column(DateTime)  # Silence alarm until this time
    acknowledged_by = Column(String(100))  # User who acknowledged
    resolved_by = Column(String(100))  # User who resolved
    
    # State tracking
    occurrence_count = Column(Integer, default=1, nullable=False)
    first_occurrence = Column(DateTime, default=get_current_time, nullable=False)
    last_occurrence = Column(DateTime, default=get_current_time, nullable=False)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    
    # Notification tracking
    notification_sent = Column(Boolean, default=False, nullable=False)
    last_notification_sent = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, default=get_current_time, nullable=False)
    updated_at = Column(DateTime, default=get_current_time, onupdate=get_current_time, nullable=False)
    
    # Relationships
    device = relationship("SNMPDevice", back_populates="alarms")
    history = relationship("AlarmHistory", back_populates="alarm", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_alarm_device', 'device_id'),
        Index('idx_alarm_status', 'status'),
        Index('idx_alarm_type', 'alarm_type'),
        Index('idx_alarm_severity', 'severity'),
        Index('idx_alarm_fingerprint', 'alarm_fingerprint'),
        Index('idx_alarm_mac', 'mac_address'),
        Index('idx_alarm_last_occurrence', 'last_occurrence'),
    )
    
    def __repr__(self) -> str:
        return f"<Alarm(id={self.id}, device_id={self.device_id}, type='{self.alarm_type}', status='{self.status}')>"


class AlarmHistory(Base):
    """
    Historical record of alarm state changes.
    """
    __tablename__ = "alarm_history"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    alarm_id = Column(Integer, ForeignKey('alarms.id', ondelete='CASCADE'), nullable=False)
    
    # Change details
    old_status = Column(Enum(AlarmStatus))
    new_status = Column(Enum(AlarmStatus), nullable=False)
    change_reason = Column(String(255))
    change_message = Column(Text)
    
    # Timestamp
    changed_at = Column(DateTime, default=get_current_time, nullable=False)
    
    # Relationships
    alarm = relationship("Alarm", back_populates="history")
    
    # Indexes
    __table_args__ = (
        Index('idx_alarm_history_alarm', 'alarm_id'),
        Index('idx_alarm_history_timestamp', 'changed_at'),
    )
    
    def __repr__(self) -> str:
        return f"<AlarmHistory(id={self.id}, alarm_id={self.alarm_id}, new_status='{self.new_status}')>"


class ChangeType(str, enum.Enum):
    """Port change type enumeration."""
    MAC_ADDED = "mac_added"
    MAC_REMOVED = "mac_removed"
    MAC_MOVED = "mac_moved"
    VLAN_CHANGED = "vlan_changed"
    DESCRIPTION_CHANGED = "description_changed"
    STATUS_CHANGED = "status_changed"


class PortChangeHistory(Base):
    """
    Track all changes to ports (MAC, VLAN, description, etc.).
    """
    __tablename__ = "port_change_history"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False)
    port_number = Column(Integer, nullable=False)
    change_type = Column(Enum(ChangeType), nullable=False)
    change_timestamp = Column(DateTime, default=get_current_time, nullable=False)
    
    # Old values
    old_value = Column(Text)
    old_mac_address = Column(String(17))
    old_vlan_id = Column(Integer)
    old_description = Column(String(255))
    
    # New values
    new_value = Column(Text)
    new_mac_address = Column(String(17))
    new_vlan_id = Column(Integer)
    new_description = Column(String(255))
    
    # Movement tracking (if MAC moved)
    from_device_id = Column(Integer)
    from_port_number = Column(Integer)
    to_device_id = Column(Integer)
    to_port_number = Column(Integer)
    
    # Change metadata
    change_details = Column(Text)
    alarm_created = Column(Boolean, default=False)
    alarm_id = Column(Integer, ForeignKey('alarms.id'))
    
    # Relationships
    device = relationship("SNMPDevice")
    alarm = relationship("Alarm")
    
    # Indexes
    __table_args__ = (
        Index('idx_pch_device_port', 'device_id', 'port_number'),
        Index('idx_pch_change_type', 'change_type'),
        Index('idx_pch_timestamp', 'change_timestamp'),
        Index('idx_pch_mac_addresses', 'old_mac_address', 'new_mac_address'),
    )
    
    def __repr__(self) -> str:
        return f"<PortChangeHistory(id={self.id}, device_id={self.device_id}, port={self.port_number}, type={self.change_type})>"


class MACAddressTracking(Base):
    """
    Track current location and history of each MAC address.
    """
    __tablename__ = "mac_address_tracking"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(17), unique=True, nullable=False)
    
    # Current location
    current_device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='SET NULL'))
    current_port_number = Column(Integer)
    current_vlan_id = Column(Integer)
    
    # Device information (from domain/DHCP)
    device_name = Column(String(255))
    ip_address = Column(String(45))
    device_type = Column(String(100))
    domain_user = Column(String(255))
    
    # Tracking metadata
    first_seen = Column(DateTime, default=get_current_time, nullable=False)
    last_seen = Column(DateTime, default=get_current_time, nullable=False)
    last_moved = Column(DateTime)
    move_count = Column(Integer, default=0)
    
    # Previous location (for quick reference)
    previous_device_id = Column(Integer)
    previous_port_number = Column(Integer)
    
    # Relationships
    current_device = relationship("SNMPDevice")
    
    # Indexes
    __table_args__ = (
        Index('idx_mat_current_location', 'current_device_id', 'current_port_number'),
        Index('idx_mat_last_seen', 'last_seen'),
    )
    
    def __repr__(self) -> str:
        return f"<MACAddressTracking(mac={self.mac_address}, device_id={self.current_device_id}, port={self.current_port_number})>"


class PortSnapshot(Base):
    """
    Store periodic snapshots of port states for comparison.
    """
    __tablename__ = "port_snapshot"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False)
    port_number = Column(Integer, nullable=False)
    snapshot_timestamp = Column(DateTime, default=get_current_time, nullable=False)
    
    # Port configuration
    port_name = Column(String(100))
    port_alias = Column(String(255))
    port_description = Column(Text)
    admin_status = Column(String(20))
    oper_status = Column(String(20))
    
    # VLAN information
    vlan_id = Column(Integer)
    vlan_name = Column(String(100))
    
    # MAC information
    mac_address = Column(String(17))
    mac_addresses = Column(Text)  # JSON array of multiple MACs
    
    # Relationships
    device = relationship("SNMPDevice")
    
    # Indexes
    __table_args__ = (
        Index('idx_ps_device_port_time', 'device_id', 'port_number', 'snapshot_timestamp'),
        Index('idx_ps_timestamp', 'snapshot_timestamp'),
    )
    
    def __repr__(self) -> str:
        return f"<PortSnapshot(id={self.id}, device_id={self.device_id}, port={self.port_number}, time={self.snapshot_timestamp})>"
