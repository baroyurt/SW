"""
Port Change Detector - Tracks and detects changes in port configurations.
Monitors MAC addresses, VLANs, descriptions, and creates alarms for changes.
"""

import logging
import json
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, text

from models.database import (
    SNMPDevice, PortStatusData, PortSnapshot, MACAddressTracking,
    PortChangeHistory, Alarm, AlarmSeverity, AlarmStatus, ChangeType
)
from core.database_manager import DatabaseManager
from core.alarm_manager import AlarmManager


class PortChangeDetector:
    """
    Detects and tracks changes in port configurations.
    Compares current state with previous snapshots to identify changes.
    """
    
    def __init__(
        self,
        db_manager: DatabaseManager,
        alarm_manager: AlarmManager
    ):
        """
        Initialize port change detector.
        
        Args:
            db_manager: Database manager
            alarm_manager: Alarm manager
        """
        self.db_manager = db_manager
        self.alarm_manager = alarm_manager
        self.logger = logging.getLogger('snmp_worker.change_detector')
        
        self.logger.info("Port Change Detector initialized")
    
    def detect_and_record_changes(
        self,
        session: Session,
        device: SNMPDevice,
        current_port_data: PortStatusData
    ) -> List[PortChangeHistory]:
        """
        Detect changes for a specific port and record them.
        
        Args:
            session: Database session
            device: Device
            current_port_data: Current port status data
            
        Returns:
            List of detected changes
        """
        changes = []
        
        # Get the previous snapshot for this port
        previous_snapshot = self._get_latest_snapshot(
            session,
            device.id,
            current_port_data.port_number
        )
        
        if not previous_snapshot:
            # First time seeing this port, create initial snapshot
            self._create_snapshot(session, device, current_port_data)
            self.logger.debug(f"Created initial snapshot for {device.name} port {current_port_data.port_number}")
            
            # Even on first scan, check for MAC configuration mismatch
            # This is important to detect if someone configured an expected MAC
            # but the actual MAC on the port is different
            mac_config_change = self._detect_mac_config_mismatch(
                session,
                device,
                current_port_data,
                None  # No previous snapshot, but we can still check expected vs actual
            )
            if mac_config_change:
                changes.append(mac_config_change)
            
            return changes
        
        # Check for MAC address changes
        mac_changes = self._detect_mac_changes(
            session,
            device,
            current_port_data,
            previous_snapshot
        )
        changes.extend(mac_changes)
        
        # Check for VLAN changes
        vlan_change = self._detect_vlan_change(
            session,
            device,
            current_port_data,
            previous_snapshot
        )
        if vlan_change:
            changes.append(vlan_change)
        
        # Check for description changes
        desc_change = self._detect_description_change(
            session,
            device,
            current_port_data,
            previous_snapshot
        )
        if desc_change:
            changes.append(desc_change)
        
        # Check for MAC address changes (comparing snapshots)
        mac_addr_change = self._detect_mac_address_change(
            session,
            device,
            current_port_data,
            previous_snapshot
        )
        if mac_addr_change:
            changes.append(mac_addr_change)
        
        # Check for MAC configuration mismatches (expected vs actual)
        mac_config_change = self._detect_mac_config_mismatch(
            session,
            device,
            current_port_data,
            previous_snapshot
        )
        if mac_config_change:
            changes.append(mac_config_change)
        
        # Check for status changes
        status_change = self._detect_status_change(
            session,
            device,
            current_port_data,
            previous_snapshot
        )
        if status_change:
            changes.append(status_change)
        
        # Create new snapshot
        self._create_snapshot(session, device, current_port_data)
        
        return changes
    
    def _get_latest_snapshot(
        self,
        session: Session,
        device_id: int,
        port_number: int
    ) -> Optional[PortSnapshot]:
        """Get the latest snapshot for a port."""
        return session.query(PortSnapshot).filter(
            and_(
                PortSnapshot.device_id == device_id,
                PortSnapshot.port_number == port_number
            )
        ).order_by(PortSnapshot.snapshot_timestamp.desc()).first()
    
    def _create_snapshot(
        self,
        session: Session,
        device: SNMPDevice,
        port_data: PortStatusData
    ) -> PortSnapshot:
        """Create a new port snapshot."""
        snapshot = PortSnapshot(
            device_id=device.id,
            port_number=port_data.port_number,
            snapshot_timestamp=datetime.utcnow(),
            port_name=port_data.port_name,
            port_alias=port_data.port_alias,
            port_description=port_data.port_description,
            admin_status=port_data.admin_status.value if port_data.admin_status else None,
            oper_status=port_data.oper_status.value if port_data.oper_status else None,
            vlan_id=port_data.vlan_id,
            vlan_name=port_data.vlan_name,
            mac_address=port_data.mac_address,
            mac_addresses=port_data.mac_addresses
        )
        session.add(snapshot)
        return snapshot
    
    def _detect_mac_changes(
        self,
        session: Session,
        device: SNMPDevice,
        current: PortStatusData,
        previous: PortSnapshot
    ) -> List[PortChangeHistory]:
        """Detect MAC address changes (added, removed, moved)."""
        changes = []
        
        # Parse current MAC addresses
        current_macs = self._parse_mac_addresses(
            current.mac_address,
            current.mac_addresses
        )
        
        # Parse previous MAC addresses
        previous_macs = self._parse_mac_addresses(
            previous.mac_address,
            previous.mac_addresses
        )
        
        # Detect new MACs
        new_macs = current_macs - previous_macs
        for mac in new_macs:
            change = self._handle_mac_added_or_moved(
                session,
                device,
                current.port_number,
                mac,
                current.vlan_id
            )
            if change:
                changes.append(change)
        
        # Detect removed MACs
        removed_macs = previous_macs - current_macs
        for mac in removed_macs:
            change = self._handle_mac_removed(
                session,
                device,
                current.port_number,
                mac
            )
            if change:
                changes.append(change)
        
        return changes
    
    def _parse_mac_addresses(
        self,
        mac_address: Optional[str],
        mac_addresses: Optional[str]
    ) -> set:
        """Parse MAC addresses from database fields."""
        macs = set()
        
        if mac_address:
            macs.add(mac_address.upper())
        
        if mac_addresses:
            try:
                mac_list = json.loads(mac_addresses)
                for mac in mac_list:
                    if mac:
                        macs.add(mac.upper())
            except (json.JSONDecodeError, TypeError):
                pass
        
        return macs
    
    def _handle_mac_added_or_moved(
        self,
        session: Session,
        device: SNMPDevice,
        port_number: int,
        mac_address: str,
        vlan_id: Optional[int]
    ) -> Optional[PortChangeHistory]:
        """
        Handle a MAC address that was added or moved to a port.
        
        Now checks against the expected MAC from ports table to avoid false alarms.
        """
        
        # First, check if there's an expected MAC for this port in ports table
        expected_mac = self._get_expected_mac_for_port(session, device, port_number)
        
        # If this port has a registered MAC and the current MAC matches it,
        # it's not a change - just the expected MAC being seen
        if expected_mac and expected_mac == mac_address.upper():
            self.logger.debug(
                f"MAC {mac_address} on {device.name} port {port_number} "
                f"matches expected/registered MAC. No alarm needed."
            )
            
            # Update MAC tracking to reflect current state
            mac_tracking = session.query(MACAddressTracking).filter(
                MACAddressTracking.mac_address == mac_address
            ).first()
            
            if mac_tracking:
                # Update existing tracking
                mac_tracking.current_device_id = device.id
                mac_tracking.current_port_number = port_number
                mac_tracking.current_vlan_id = vlan_id
                mac_tracking.last_seen = datetime.utcnow()
            else:
                # Create new tracking for expected MAC
                mac_tracking = MACAddressTracking(
                    mac_address=mac_address,
                    current_device_id=device.id,
                    current_port_number=port_number,
                    current_vlan_id=vlan_id,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    move_count=0
                )
                session.add(mac_tracking)
            
            # No alarm - this is expected
            return None
        
        # If there's an expected MAC but it doesn't match, this is a problem!
        if expected_mac and expected_mac != mac_address.upper():
            self.logger.warning(
                f"MAC MISMATCH on {device.name} port {port_number}! "
                f"Expected: {expected_mac}, Found: {mac_address}"
            )
            # Continue to create alarm - this is an unexpected MAC change
        
        # Check if MAC exists in tracking table
        mac_tracking = session.query(MACAddressTracking).filter(
            MACAddressTracking.mac_address == mac_address
        ).first()
        
        if mac_tracking:
            # MAC exists - check if it moved
            if (mac_tracking.current_device_id != device.id or
                mac_tracking.current_port_number != port_number):
                
                # Check if MAC is moving to its registered port (Issue: false alarms fix)
                # Even for existing MACs, we should check if they're on their registered port
                registered_location = self._get_registered_mac_location(session, mac_address)
                if registered_location:
                    reg_device, reg_port, reg_device_info = registered_location
                    
                    # If MAC detected on its registered port, this is expected - no alarm
                    if reg_device == device.name and reg_port == port_number:
                        self.logger.debug(
                            f"MAC {mac_address} detected on registered port "
                            f"{device.name} port {port_number}. "
                            f"Updating tracking without alarm."
                        )
                        # Update MAC tracking data without creating alarm
                        mac_tracking.previous_device_id = mac_tracking.current_device_id
                        mac_tracking.previous_port_number = mac_tracking.current_port_number
                        mac_tracking.current_device_id = device.id
                        mac_tracking.current_port_number = port_number
                        mac_tracking.current_vlan_id = vlan_id
                        mac_tracking.last_seen = datetime.utcnow()
                        return None  # No alarm
                
                # MAC moved to a different port (not registered port)
                old_device = None
                if mac_tracking.current_device_id:
                    old_device = session.query(SNMPDevice).filter(
                        SNMPDevice.id == mac_tracking.current_device_id
                    ).first()
                
                change = self._record_mac_moved(
                    session,
                    mac_address,
                    old_device,
                    mac_tracking.current_port_number,
                    device,
                    port_number,
                    vlan_id,
                    old_vlan_id=mac_tracking.current_vlan_id
                )
                
                # Update MAC tracking
                mac_tracking.previous_device_id = mac_tracking.current_device_id
                mac_tracking.previous_port_number = mac_tracking.current_port_number
                mac_tracking.current_device_id = device.id
                mac_tracking.current_port_number = port_number
                mac_tracking.current_vlan_id = vlan_id
                mac_tracking.last_moved = datetime.utcnow()
                mac_tracking.last_seen = datetime.utcnow()
                mac_tracking.move_count += 1
                
                return change
            else:
                # Same location, just update last_seen
                mac_tracking.last_seen = datetime.utcnow()
                return None
        else:
            # New MAC - create tracking entry
            mac_tracking = MACAddressTracking(
                mac_address=mac_address,
                current_device_id=device.id,
                current_port_number=port_number,
                current_vlan_id=vlan_id,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                move_count=0
            )
            session.add(mac_tracking)
            
            # Check if this MAC is registered in ports table (Issue: false alarms fix)
            # Even for new MACs, we should check if they're on their registered port
            registered_location = self._get_registered_mac_location(session, mac_address)
            if registered_location:
                reg_device, reg_port, reg_device_info = registered_location
                
                # If MAC detected on its registered port, this is expected - no alarm
                if reg_device == device.name and reg_port == port_number:
                    self.logger.debug(
                        f"New MAC {mac_address} detected on registered port "
                        f"{device.name} port {port_number}. No alarm needed."
                    )
                    # Don't create alarm or history - this is the expected configuration
                    return None
            
            # Record as new MAC (only if not on registered port)
            change = self._record_mac_added(
                session,
                device,
                port_number,
                mac_address,
                vlan_id
            )
            return change
    
    def _handle_mac_removed(
        self,
        session: Session,
        device: SNMPDevice,
        port_number: int,
        mac_address: str
    ) -> Optional[PortChangeHistory]:
        """Handle a MAC address that was removed from a port."""
        
        # Update MAC tracking - set current location to null
        mac_tracking = session.query(MACAddressTracking).filter(
            MACAddressTracking.mac_address == mac_address
        ).first()
        
        if mac_tracking:
            mac_tracking.previous_device_id = mac_tracking.current_device_id
            mac_tracking.previous_port_number = mac_tracking.current_port_number
            mac_tracking.current_device_id = None
            mac_tracking.current_port_number = None
            mac_tracking.last_seen = datetime.utcnow()
        
        # Record the removal
        change = PortChangeHistory(
            device_id=device.id,
            port_number=port_number,
            change_type=ChangeType.MAC_REMOVED,
            change_timestamp=datetime.utcnow(),
            old_mac_address=mac_address,
            change_details=f"MAC address {mac_address} removed from port {port_number}"
        )
        session.add(change)
        
        return change
    
    def _get_port_connection_info(
        self,
        session: Session,
        device: SNMPDevice,
        port_number: int
    ) -> Optional[str]:
        """
        Get port connection info from ports table (connected_to field).
        This is the user-configured port connection via 'Edit Port Connection' menu.
        
        Args:
            session: Database session
            device: SNMP Device
            port_number: Port number
            
        Returns:
            connected_to field value or None
        
        Note: Uses raw SQL because ports and switches tables are legacy tables
        not yet integrated into the SQLAlchemy ORM models. This is intentional
        to maintain compatibility with the existing web interface.
        """
        try:
            # Query ports table using raw SQL
            # Join with switches table to match by device name
            # Note: These are legacy tables not in ORM, raw SQL is required
            result = session.execute(
                text("""
                SELECT p.connected_to 
                FROM ports p
                JOIN switches s ON p.switch_id = s.id
                WHERE s.name = :device_name AND p.port_no = :port_number
                LIMIT 1
                """),
                {"device_name": device.name, "port_number": port_number}
            )
            row = result.fetchone()
            if row and row[0]:
                return row[0]
        except Exception as e:
            self.logger.debug(f"Could not query ports table: {e}")
        
        return None
    
    def _get_registered_mac_location(
        self,
        session: Session,
        mac_address: str
    ) -> Optional[Tuple[str, int, str]]:
        """
        Check if MAC address is registered in ports table and get its location.
        
        Args:
            session: Database session
            mac_address: MAC address to search for
            
        Returns:
            Tuple of (device_name, port_number, device_info) or None if not found
            device_info contains the registered device name/description
        
        Note: Uses raw SQL to query legacy ports table.
        """
        try:
            # Normalize MAC address to uppercase for comparison
            mac_upper = mac_address.upper() if mac_address else ""
            
            # Query ports table for this MAC address
            # Check both 'mac' field and connected_to field for device info
            result = session.execute(
                text("""
                SELECT s.name, p.port_no, p.device, p.connected_to
                FROM ports p
                JOIN switches s ON p.switch_id = s.id
                WHERE UPPER(p.mac) = :mac_address
                LIMIT 1
                """),
                {"mac_address": mac_upper}
            )
            row = result.fetchone()
            if row:
                device_name = row[0]
                port_number = row[1]
                device_info = row[2] or row[3] or "DEVICE"  # Use device field or connected_to, default to "DEVICE"
                return (device_name, port_number, device_info)
        except Exception as e:
            self.logger.debug(f"Could not query ports table for MAC: {e}")
        
        return None
    
    def _get_expected_mac_for_port(
        self,
        session: Session,
        device: SNMPDevice,
        port_number: int
    ) -> Optional[str]:
        """
        Get the expected/registered MAC address for a specific port from ports table.
        
        Args:
            session: Database session
            device: SNMP Device
            port_number: Port number
            
        Returns:
            Expected MAC address (uppercase) or None if not registered
        
        Note: Uses raw SQL to query legacy ports table.
        This is the "official" MAC that should be on this port according to user configuration.
        """
        try:
            # Query ports table for the MAC registered for this specific port
            result = session.execute(
                text("""
                SELECT UPPER(p.mac)
                FROM ports p
                JOIN switches s ON p.switch_id = s.id
                WHERE s.name = :device_name 
                AND p.port_no = :port_number
                AND p.mac IS NOT NULL
                AND p.mac != ''
                LIMIT 1
                """),
                {"device_name": device.name, "port_number": port_number}
            )
            row = result.fetchone()
            if row and row[0]:
                return row[0]  # Return uppercase MAC
        except Exception as e:
            self.logger.debug(f"Could not query expected MAC for port: {e}")
        
        return None
    
    def _record_mac_moved(
        self,
        session: Session,
        mac_address: str,
        old_device: Optional[SNMPDevice],
        old_port: Optional[int],
        new_device: SNMPDevice,
        new_port: int,
        vlan_id: Optional[int],
        old_vlan_id: Optional[int] = None
    ) -> PortChangeHistory:
        """Record a MAC address movement and create alarm."""
        
        old_device_name = old_device.name if old_device else "Unknown"
        old_port_str = str(old_port) if old_port else "Unknown"
        
        # Check if the new port has a configured connection in ports table
        port_connection_info = self._get_port_connection_info(session, new_device, new_port)
        
        # Check if this MAC is registered in the ports table (Issue #1 fix)
        registered_location = self._get_registered_mac_location(session, mac_address)
        
        # Check if MAC is actually moving or just being re-detected on same configured port
        actual_old_value = f"{old_device_name} port {old_port_str}"
        actual_new_value = f"{new_device.name} port {new_port}"
        
        # Determine the expected old value based on available information
        display_old_value = actual_old_value
        
        # If MAC is registered in ports table, use that as the expected/old location
        if registered_location and old_device_name == "Unknown":
            reg_device, reg_port, reg_device_info = registered_location
            display_old_value = f"{reg_device} port {reg_port}"
            self.logger.info(
                f"MAC {mac_address} is registered in ports table at "
                f"{reg_device} port {reg_port}. Using this as old value."
            )
            
            # Check if MAC is still on the same registered location
            if reg_device == new_device.name and reg_port == new_port:
                self.logger.debug(
                    f"MAC {mac_address} detected on registered location "
                    f"{new_device.name} port {new_port}. No real movement - skipping alarm."
                )
                # Still create history but don't create alarm
                change = PortChangeHistory(
                    device_id=new_device.id,
                    port_number=new_port,
                    change_type=ChangeType.MAC_ADDED,
                    change_timestamp=datetime.utcnow(),
                    new_mac_address=mac_address,
                    new_vlan_id=vlan_id,
                    change_details=f"MAC {mac_address} detected on registered port {new_device.name} port {new_port}"
                )
                session.add(change)
                return change
        # Otherwise, use configured port connection info if available
        elif port_connection_info and old_device_name == "Unknown":
            display_old_value = port_connection_info
        
        # Legacy check: If port has configured connection and MAC appears to come from "Unknown",
        # but the port already has this connection configured, it's not really a move
        if (port_connection_info and 
            old_device_name == "Unknown" and 
            old_port_str == "Unknown" and
            not registered_location):  # Only if MAC is not registered
            # This means the MAC is appearing on a port that's already configured for it
            self.logger.debug(
                f"MAC {mac_address} detected on {new_device.name} port {new_port} "
                f"which has configured connection. Skipping alarm as it's not a real movement."
            )
            # Still create history but don't create alarm
            change = PortChangeHistory(
                device_id=new_device.id,
                port_number=new_port,
                change_type=ChangeType.MAC_ADDED,  # Treat as addition, not movement
                change_timestamp=datetime.utcnow(),
                new_mac_address=mac_address,
                new_vlan_id=vlan_id,
                change_details=f"MAC {mac_address} detected on {new_device.name} port {new_port} (configured port)"
            )
            session.add(change)
            return change
        
        change_details = (
            f"MAC {mac_address} moved from {old_device_name} port {old_port_str} "
            f"to {new_device.name} port {new_port}"
        )
        
        # Create change history entry
        change = PortChangeHistory(
            device_id=new_device.id,
            port_number=new_port,
            change_type=ChangeType.MAC_MOVED,
            change_timestamp=datetime.utcnow(),
            old_mac_address=mac_address,
            new_mac_address=mac_address,
            from_device_id=old_device.id if old_device else None,
            from_port_number=old_port,
            to_device_id=new_device.id,
            to_port_number=new_port,
            new_vlan_id=vlan_id,
            change_details=change_details
        )
        session.add(change)
        session.flush()
        
        # Create alarm for MAC movement
        alarm, is_new = self.db_manager.get_or_create_alarm(
            session,
            new_device,
            "mac_moved",
            "HIGH",
            f"MAC {mac_address} moved to port {new_port}",
            change_details,
            port_number=new_port,
            mac_address=mac_address,
            from_port=old_port,
            to_port=new_port,
            old_vlan_id=old_vlan_id,
            new_vlan_id=vlan_id
        )
        
        if alarm:
            change.alarm_created = True
            change.alarm_id = alarm.id
            
            # Add old/new value details to alarm - use configured port info if available
            alarm.old_value = display_old_value
            alarm.new_value = actual_new_value
            
            # Send notifications
            if is_new:
                self.alarm_manager._send_notifications(
                    new_device,
                    "mac_moved",
                    "HIGH",
                    change_details,
                    port_number=new_port,
                    port_name=f"Port {new_port}"
                )
                alarm.notification_sent = True
                alarm.last_notification_sent = datetime.utcnow()
        
        self.logger.warning(change_details)
        
        return change
    
    def _record_mac_added(
        self,
        session: Session,
        device: SNMPDevice,
        port_number: int,
        mac_address: str,
        vlan_id: Optional[int]
    ) -> PortChangeHistory:
        """Record a new MAC address on a port."""
        
        change_details = f"New MAC {mac_address} detected on {device.name} port {port_number}"
        
        change = PortChangeHistory(
            device_id=device.id,
            port_number=port_number,
            change_type=ChangeType.MAC_ADDED,
            change_timestamp=datetime.utcnow(),
            new_mac_address=mac_address,
            new_vlan_id=vlan_id,
            change_details=change_details
        )
        session.add(change)
        
        self.logger.info(change_details)
        
        return change
    
    def _detect_vlan_change(
        self,
        session: Session,
        device: SNMPDevice,
        current: PortStatusData,
        previous: PortSnapshot
    ) -> Optional[PortChangeHistory]:
        """Detect VLAN changes."""
        
        def _is_default_vlan(v):
            """None / 0 / 1 are all 'unset/default' – not a meaningful VLAN."""
            return v is None or v in (0, 1)

        if current.vlan_id != previous.vlan_id and not (
            _is_default_vlan(current.vlan_id) and _is_default_vlan(previous.vlan_id)
        ):
            change_details = (
                f"{device.name} port {current.port_number} VLAN değişti: "
                f"{previous.vlan_id or 'Bilinmiyor'} → {current.vlan_id or 'Bilinmiyor'}"
            )
            
            change = PortChangeHistory(
                device_id=device.id,
                port_number=current.port_number,
                change_type=ChangeType.VLAN_CHANGED,
                change_timestamp=datetime.utcnow(),
                old_vlan_id=previous.vlan_id,
                new_vlan_id=current.vlan_id,
                old_value=previous.vlan_name,
                new_value=current.vlan_name,
                change_details=change_details
            )
            session.add(change)
            session.flush()
            
            # Create alarm for VLAN change
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                "vlan_changed",
                "MEDIUM",
                f"VLAN değişti: Port {current.port_number}",
                change_details,
                port_number=current.port_number
            )
            
            if alarm:
                change.alarm_created = True
                change.alarm_id = alarm.id
                alarm.old_value = str(previous.vlan_id or 'None')
                alarm.new_value = str(current.vlan_id or 'None')
            
            self.logger.info(change_details)
            
            return change
        
        return None
    
    def _detect_description_change(
        self,
        session: Session,
        device: SNMPDevice,
        current: PortStatusData,
        previous: PortSnapshot
    ) -> Optional[PortChangeHistory]:
        """Detect port description changes."""
        
        current_desc = current.port_alias or current.port_description or ""
        previous_desc = previous.port_alias or previous.port_description or ""
        
        if current_desc != previous_desc:
            change_details = (
                f"{device.name} port {current.port_number} açıklama değişti: "
                f"'{previous_desc}' → '{current_desc}'"
            )
            
            change = PortChangeHistory(
                device_id=device.id,
                port_number=current.port_number,
                change_type=ChangeType.DESCRIPTION_CHANGED,
                change_timestamp=datetime.utcnow(),
                old_description=previous_desc,
                new_description=current_desc,
                change_details=change_details
            )
            session.add(change)
            session.flush()
            
            # Create alarm for description change
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                "description_changed",
                "MEDIUM",
                f"Açıklama değişti: Port {current.port_number}",
                change_details,
                port_number=current.port_number
            )
            
            if alarm:
                change.alarm_created = True
                change.alarm_id = alarm.id
                alarm.old_value = previous_desc or '(empty)'
                alarm.new_value = current_desc or '(empty)'
            
            self.logger.info(change_details)
            
            return change
        
        return None
    
    def _detect_mac_address_change(
        self,
        session: Session,
        device: SNMPDevice,
        current: PortStatusData,
        previous: PortSnapshot
    ) -> Optional[PortChangeHistory]:
        """
        SNMP snapshot'ları karşılaştırarak MAC adresi değişikliklerini tespit et.
        
        Detect MAC address changes by comparing current vs previous snapshot.
        
        TÜRKÇE AÇIKLAMA:
        Bu fonksiyon, SNMP'nin önceki taramada gördüğü MAC ile şimdiki taramada
        gördüğü MAC'i karşılaştırır. Fiziksel olarak cihaz değiştirildiğinde çalışır.
        
        FARK NEDİR?
        1. _detect_mac_address_change (BU FONKSİYON):
           - SNMP önceki tarama: MAC = 12:74
           - SNMP şimdiki tarama: MAC = 12:6a
           - Fiziksel cihaz değişti, alarm oluştur
        
        2. _detect_mac_config_mismatch (DİĞER FONKSİYON):
           - Kullanıcı UI'da kaydettiği: MAC = 12:6a
           - SNMP cihazdan okuduğu: MAC = 12:74
           - Kullanıcının beklediği ile gerçek farklı, alarm oluştur
        
        Similar to description change detection, this creates an alarm when
        the MAC address on a port changes, showing old and new values.
        This is independent of the "expected MAC" configuration check.
        """
        
        current_mac = current.mac_address.upper() if current.mac_address else ""
        previous_mac = previous.mac_address.upper() if previous.mac_address else ""
        
        # Normalize empty strings
        current_mac = current_mac.strip()
        previous_mac = previous_mac.strip()
        
        # DEBUG LOGGING - Her zaman göster
        self.logger.info("=" * 80)
        self.logger.info(f"🔍 MAC DEĞİŞİKLİĞİ KONTROLÜ - {device.name} Port {current.port_number}")
        self.logger.info(f"   Önceki MAC: '{previous_mac}'")
        self.logger.info(f"   Şimdiki MAC: '{current_mac}'")
        self.logger.info(f"   Eşit mi? {current_mac == previous_mac}")
        self.logger.info("=" * 80)
        
        if current_mac != previous_mac:
            # ÖNEMLI: Sadece MAC-to-MAC değişikliklerinde alarm oluştur
            # Empty durumları (cihaz çıkarıldı/takıldı) için alarm oluşturma
            # IMPORTANT: Only create alarm for MAC-to-MAC changes
            # Don't alarm on empty states (device disconnected/connected)
            
            # Check if this is a meaningful change (both MACs are non-empty)
            both_have_mac = bool(previous_mac) and bool(current_mac)
            
            self.logger.warning("=" * 80)
            self.logger.warning(f"🔍 _detect_mac_address_change ÇALIŞTI")
            self.logger.warning(f"   Önceki MAC: '{previous_mac}'")
            self.logger.warning(f"   Şimdiki MAC: '{current_mac}'")
            self.logger.warning(f"   both_have_mac: {both_have_mac}")
            self.logger.warning("=" * 80)
            
            if not both_have_mac:
                # One or both MACs are empty - this is connect/disconnect, not device swap
                self.logger.info(
                    f"   ℹ️ MAC değişikliği tespit edildi ama alarm oluşturulmayacak: "
                    f"'{previous_mac or '(boş)'}' → '{current_mac or '(boş)'}'"
                )
                if not previous_mac and current_mac:
                    self.logger.info(f"   Sebep: Yeni cihaz bağlandı (empty → MAC)")
                elif previous_mac and not current_mac:
                    self.logger.info(f"   Sebep: Cihaz çıkarıldı (MAC → empty)")
                else:
                    self.logger.info(f"   Sebep: Her ikisi de boş")
                
                # Still create change history but no alarm
                change = PortChangeHistory(
                    device_id=device.id,
                    port_number=current.port_number,
                    change_type=ChangeType.MAC_MOVED,
                    change_timestamp=datetime.utcnow(),
                    old_mac_address=previous_mac or None,
                    new_mac_address=current_mac or None,
                    change_details=(
                        f"{device.name} port {current.port_number} MAC değişti: "
                        f"'{previous_mac or '(boş)'}' → '{current_mac or '(boş)'}' "
                        f"(alarm yok - cihaz {'bağlandı' if current_mac else 'ayrıldı'})"
                    )
                )
                session.add(change)
                self.logger.debug(f"   Change history kaydedildi (alarm olmadan)")
                return change
            
            # Both MACs are non-empty - this is a device swap, create alarm!
            change_details = (
                f"{device.name} port {current.port_number} MAC adresi değişti: "
                f"'{previous_mac}' → '{current_mac}'"
            )
            
            self.logger.warning("🚨 MAC DEĞİŞİKLİĞİ TESPİT EDİLDİ!")
            self.logger.warning(f"   Change Details: {change_details}")
            
            change = PortChangeHistory(
                device_id=device.id,
                port_number=current.port_number,
                change_type=ChangeType.MAC_MOVED,  # Reuse MAC_MOVED type
                change_timestamp=datetime.utcnow(),
                old_mac_address=previous_mac or None,
                new_mac_address=current_mac or None,
                change_details=change_details
            )
            session.add(change)
            session.flush()
            
            self.logger.warning(f"   ✅ Change History kaydedildi (ID: {change.id})")
            
            # Create alarm for MAC address change
            self.logger.warning(f"   📢 Alarm oluşturuluyor...")
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                "mac_moved",
                "HIGH",  # High severity like other MAC alarms
                f"MAC adresi değişti: Port {current.port_number}",
                change_details,
                port_number=current.port_number,
                mac_address=current_mac or None
            )
            
            if alarm:
                self.logger.warning(f"   ✅ Alarm {'OLUŞTURULDU' if is_new else 'GÜNCELLENDI'} (ID: {alarm.id})")
                change.alarm_created = True
                change.alarm_id = alarm.id
                # Açıklama değişikliği gibi format
                # Format like description changes
                alarm.old_value = previous_mac or '(empty)'
                alarm.new_value = current_mac or '(empty)'
                
                self.logger.warning(f"   Alarm Old Value: {alarm.old_value}")
                self.logger.warning(f"   Alarm New Value: {alarm.new_value}")
                
                # Send notifications for new alarms
                if is_new:
                    self.logger.warning(f"   📧 Bildirim gönderiliyor...")
                    self.alarm_manager._send_notifications(
                        device,
                        "mac_moved",
                        "HIGH",
                        change_details,
                        port_number=current.port_number,
                        port_name=f"Port {current.port_number}"
                    )
                    alarm.notification_sent = True
                    alarm.last_notification_sent = datetime.utcnow()
                    self.logger.warning(f"   ✅ Bildirim gönderildi!")
                else:
                    self.logger.warning(f"   ⚠️ Yeni alarm değil, bildirim gönderilmedi")
            else:
                self.logger.error(f"   ❌ ALARM OLUŞTURULAMADI!")
            
            self.logger.warning(change_details)
            
            return change
        else:
            self.logger.debug(f"   ℹ️ MAC değişmedi, alarm gerekmiyor")
        
        return None
    
    def _detect_mac_config_mismatch(
        self,
        session: Session,
        device: SNMPDevice,
        current: PortStatusData,
        previous: PortSnapshot
    ) -> Optional[PortChangeHistory]:
        """
        MAC adresi yapılandırma uyuşmazlıklarını tespit et.
        
        Detect MAC address configuration mismatches.
        
        TÜRKÇE AÇIKLAMA:
        Bu fonksiyon, kullanıcının ports tablosunda kaydettiği "beklenen MAC" ile
        SNMP'nin cihazdan okuduğu "gerçek MAC" arasındaki farkı kontrol eder.
        
        FARK NEDİR?
        - Açıklama değişikliği: SNMP switch'ten okur, switch üzerinde değişir
        - MAC değişikliği: Kullanıcı UI'da değiştirir ama cihaz aynı kalır
        
        SENARYO:
        1. Kullanıcı port'a MAC adresi yazıyor (ör: d0:ad:08:e4:12:6a)
        2. SNMP cihazdan farklı MAC görüyor (ör: d0:ad:08:e4:12:74)
        3. Bu fonksiyon uyuşmazlığı tespit edip alarm oluşturuyor
        
        Checks if the MAC address configured in the ports table differs from
        what SNMP actually finds on the port. This detects cases where:
        1. User manually configures an expected MAC in the ports table
        2. SNMP discovers a different MAC on that port
        3. This indicates unauthorized device or configuration error
        """
        
        # Get the expected/configured MAC from ports table
        # Ports tablosundan beklenen/yapılandırılmış MAC'i al
        expected_mac = self._get_expected_mac_for_port(session, device, current.port_number)
        
        self.logger.debug(
            f"MAC config check for {device.name} port {current.port_number}: "
            f"expected={expected_mac}"
        )
        
        # If no expected MAC is configured, nothing to check
        # Beklenen MAC yapılandırılmamışsa, kontrol etmeye gerek yok
        if not expected_mac:
            self.logger.debug(f"No expected MAC configured for port {current.port_number}, skipping check")
            return None
        
        # Get current MAC from SNMP data
        # SNMP verilerinden mevcut MAC'i al
        current_macs = self._parse_mac_addresses(
            current.mac_address,
            current.mac_addresses
        )
        
        self.logger.debug(
            f"Current MACs on port {current.port_number}: {current_macs}"
        )
        
        # Check if expected MAC is present
        # Beklenen MAC mevcut mu kontrol et
        if expected_mac in current_macs:
            # Expected MAC found - no mismatch
            # Beklenen MAC bulundu - uyuşmazlık yok
            self.logger.debug(
                f"Expected MAC {expected_mac} found on port {current.port_number} - no alarm"
            )
            return None
        
        # Mismatch detected! Expected MAC not found on port
        # Uyuşmazlık tespit edildi! Beklenen MAC port'ta bulunamadı
        
        # Determine what MAC is actually there
        actual_mac = current.mac_address.upper() if current.mac_address else None
        
        # Check if port has no MAC (device disconnected)
        # Port'ta MAC var mı kontrol et (cihaz bağlantısı kesilmiş olabilir)
        if not current_macs:
            # Port is empty but we expected a MAC
            # Check if we already have a tracking entry for this port
            mac_tracking = session.query(MACAddressTracking).filter(
                MACAddressTracking.current_device_id == device.id,
                MACAddressTracking.current_port_number == current.port_number,
                MACAddressTracking.mac_address == expected_mac
            ).first()
            
            # If MAC tracking exists and shows this MAC was on this port before,
            # we already know about it. Don't create repeated "no MAC" alarms.
            # This prevents alarm spam when device stays disconnected.
            if mac_tracking and mac_tracking.last_seen:
                # Device was here before, now gone - but we already tracked it
                self.logger.info(
                    f"Port {current.port_number} has no MAC address (device disconnected). "
                    f"Expected MAC '{expected_mac}' but port is empty. "
                    f"MAC was last seen at {mac_tracking.last_seen}. "
                    f"Skipping repeated 'no MAC' alarm."
                )
                return None
            
            # No tracking record - this is unusual (expected MAC configured but never seen)
            # Log but don't create alarm for this case
            self.logger.info(
                f"Port {current.port_number} has no MAC address. Expected MAC '{expected_mac}' "
                f"but port is empty and MAC was never tracked. Skipping alarm."
            )
            return None
        
        # Port has MAC(s) but not the expected one - this IS a real mismatch
        # Port'ta MAC var ama beklenen değil - bu GERÇEK bir uyuşmazlık
        actual_mac_list = ', '.join(sorted(current_macs))
        change_details = (
            f"{device.name} port {current.port_number} MAC uyuşmazlığı: "
            f"Beklenen '{expected_mac}' ancak bulunan '{actual_mac_list}'"
        )
        
        self.logger.warning("=" * 80)
        self.logger.warning(f"⚠️ ⚠️ ⚠️  MAC CONFIGURATION MISMATCH DETECTED  ⚠️ ⚠️ ⚠️")
        self.logger.warning(f"Device: {device.name}, Port: {current.port_number}")
        self.logger.warning(f"Expected MAC: {expected_mac}")
        self.logger.warning(f"Actual MAC(s): {actual_mac_list}")
        self.logger.warning(f"Details: {change_details}")
        self.logger.warning("=" * 80)
        
        # Create change history record
        change = PortChangeHistory(
            device_id=device.id,
            port_number=current.port_number,
            change_type=ChangeType.MAC_MOVED,  # Reuse MAC_MOVED type as it's conceptually similar
            change_timestamp=datetime.utcnow(),
            change_details=change_details
        )
        session.add(change)
        session.flush()
        
        self.logger.warning(f"✅ Creating MAC mismatch alarm for {device.name} port {current.port_number}")
        
        # Use the first actual MAC for alarm fingerprint (or all if multiple)
        # current_macs is a SET, need to convert to list to get first element
        alarm_mac = list(current_macs)[0] if current_macs else None
        
        # Create alarm for MAC mismatch
        # IMPORTANT: skip_whitelist=True because this is a configuration mismatch
        # User expects one MAC but SNMP sees another - whitelist shouldn't suppress this
        # Kullanıcı bir MAC bekliyor ama SNMP başka MAC görüyor - whitelist bunu suppress etmemeli
        alarm, is_new = self.db_manager.get_or_create_alarm(
            session,
            device,
            "mac_moved",  # Use mac_moved alarm type
            "HIGH",  # High severity - unauthorized MAC
            f"MAC uyuşmazlığı: Port {current.port_number}",
            change_details,
            port_number=current.port_number,
            mac_address=alarm_mac,  # Include MAC in fingerprint
            skip_whitelist=True  # Skip whitelist for configuration mismatches
        )
        
        if alarm:
            change.alarm_created = True
            change.alarm_id = alarm.id
            # AÇIKLAMA DEĞİŞİKLİĞİ GİBİ FORMAT: Eski Değer / Yeni Değer
            # Format like description changes: Old Value / New Value
            alarm.old_value = expected_mac  # Kullanıcının beklediği MAC (UI'da yazdığı)
            alarm.new_value = actual_mac_list  # SNMP'nin gördüğü gerçek MAC
            
            # Send notifications for new alarms
            if is_new:
                self.alarm_manager._send_notifications(
                    device,
                    "mac_moved",
                    "HIGH",
                    change_details,
                    port_number=current.port_number,
                    port_name=f"Port {current.port_number}"
                )
                alarm.notification_sent = True
                alarm.last_notification_sent = datetime.utcnow()
            
            self.logger.warning("=" * 80)
            self.logger.warning(f"✅ ✅ ✅  MAC MISMATCH ALARM CREATED SUCCESSFULLY  ✅ ✅ ✅")
            self.logger.warning(f"Alarm ID: {alarm.id}")
            self.logger.warning(f"Is New: {is_new}")
            self.logger.warning(f"Notification Sent: {is_new}")
            self.logger.warning(f"Old Value (Expected): {alarm.old_value}")
            self.logger.warning(f"New Value (Found): {alarm.new_value}")
            self.logger.warning(f"Severity: HIGH")
            self.logger.warning("=" * 80)
        else:
            self.logger.error("=" * 80)
            self.logger.error(f"❌ ❌ ❌  FAILED TO CREATE MAC MISMATCH ALARM  ❌ ❌ ❌")
            self.logger.error(f"Device: {device.name}, Port: {current.port_number}")
            self.logger.error("=" * 80)
        
        return change
    
    def _detect_status_change(
        self,
        session: Session,
        device: SNMPDevice,
        current: PortStatusData,
        previous: PortSnapshot
    ) -> Optional[PortChangeHistory]:
        """Detect operational status changes."""
        
        current_status = current.oper_status.value if current.oper_status else None
        previous_status = previous.oper_status
        
        if current_status != previous_status:
            change_details = (
                f"{device.name} port {current.port_number} durum değişti: "
                f"{previous_status} → {current_status}"
            )
            
            change = PortChangeHistory(
                device_id=device.id,
                port_number=current.port_number,
                change_type=ChangeType.STATUS_CHANGED,
                change_timestamp=datetime.utcnow(),
                old_value=previous_status,
                new_value=current_status,
                change_details=change_details
            )
            session.add(change)
            
            self.logger.info(change_details)
            
            return change
        
        return None
    
    def cleanup_old_snapshots(self, session: Session, days: int = 30) -> int:
        """
        Clean up snapshots older than specified days.
        
        Args:
            session: Database session
            days: Number of days to keep
            
        Returns:
            Number of snapshots deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        deleted = session.query(PortSnapshot).filter(
            PortSnapshot.snapshot_timestamp < cutoff_date
        ).delete()
        
        self.logger.info(f"Cleaned up {deleted} old port snapshots")
        
        return deleted
