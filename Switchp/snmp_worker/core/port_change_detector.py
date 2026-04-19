"""
Port Change Detector - Tracks and detects changes in port configurations.
Monitors MAC addresses, VLANs, descriptions, and creates alarms for changes.
"""

import logging
import json
import re
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, text, bindparam

from models.database import (
    SNMPDevice, PortStatusData, PortSnapshot, MACAddressTracking,
    PortChangeHistory, Alarm, AlarmSeverity, AlarmStatus, ChangeType
)
from core.database_manager import DatabaseManager
from core.alarm_manager import AlarmManager
from services.autosync_service import VLAN_TYPE_MAP, _AUTO_REGISTER_VLANS

# Grace period constants for MAC mismatch detection.
# Standard device ports: 1 hour (covers brief FDB cache flushes).
# Trunk/AP uplink ports: 24 hours (AP management MAC may be absent for
# extended periods during heavy wireless-client traffic — normal behaviour).
_GRACE_PERIOD_STANDARD_SECS = 3600
_GRACE_PERIOD_AP_TRUNK_SECS = 86400

# VLAN-based alarm suppression.
# SUPPRESS_ALARM_VLANS: These VLANs generate no MAC-change alarms at all
#   (e.g. VLAN 30 – high-churn wireless/management VLANs).
# LONG_GRACE_VLANS: For these VLANs a 30-minute absence is required before
#   a "missing MAC" alarm fires (e.g. VLAN 1, 150, 1500 – JACKPOT/gaming devices
#   that frequently age out of the FDB between polling cycles).
_SUPPRESS_ALARM_VLANS: frozenset = frozenset({30})
_LONG_GRACE_VLANS: frozenset = frozenset({1, 150, 1500})
_LONG_GRACE_PERIOD_SECS: int = 1800  # 30 minutes

# Ports with this many or more distinct MACs in their FDB entry are treated as
# AP / hub ports even if they have a VLAN assigned.  On such ports a single
# registered MAC in mac_device_registry simply means the AP device itself was
# once seen; the wireless clients it serves are NOT the registered MAC, so
# MAC-mismatch alarms must be suppressed.
_AP_PORT_MAC_COUNT_THRESHOLD: int = 4

# Uplink / trunk ports that behave like Port-Channel (Po1) interfaces.
# These backbone ports carry traffic for many devices and therefore see an
# unlimited number of MAC addresses.  Only port-status (up/down) changes are
# monitored; all MAC-change detection is skipped to avoid alarm floods.
# Format: frozenset of (device_name, port_number) tuples.
_UPLINK_PORTS: frozenset = frozenset({
    ("SW38-BEACH", 1),
})

# AP native VLAN debounce constants.
# Ports whose PVID (dot1qPvid) == _AP_NATIVE_VLAN are AP trunk uplink ports.
# The AP physical MAC lives in VLAN 70; WiFi client MACs live in companion VLANs
# (30, 40, 50, 130, 140, 254).  The AP management MAC occasionally ages out of
# the FDB while WiFi client MACs remain, causing transient "expected MAC absent"
# conditions.  Require _AP_MAC_MISS_THRESHOLD consecutive poll-cycles where the
# physical MAC is absent before raising a MAC Taşındı alarm — this eliminates
# false alarms from normal AP FDB ageing while still detecting real AP replacements.
_AP_NATIVE_VLAN: int = 70
_AP_MAC_MISS_THRESHOLD: int = 4


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

        # Per-port miss counter for AP native-VLAN (VLAN 70) MAC debounce.
        # Key: (device_name, port_number) — Value: consecutive poll-cycles where
        # the expected physical MAC was absent from the FDB.
        # Cleared to 0 when the expected MAC is found again.
        self._ap_mac_miss_counts: Dict[Tuple[str, int], int] = {}

        # Batch last_seen update buffer — accumulates MAC addresses whose only
        # required change is updating last_seen to NOW().  Flushed at the end of
        # each device's save_to_database call via flush_last_seen_batch() using a
        # single UPDATE … WHERE mac_address IN (…) instead of N individual ORM
        # updates.  This eliminates the N-row serial UPDATE pattern that was the
        # direct source of MySQL deadlock 1213 when db_max_workers > 1.
        self._last_seen_batch: List[str] = []

        self.logger.info("Port Change Detector initialized")

    def _alarm_severity(self, session: Session, alarm_type: str, default: str = "MEDIUM") -> str:
        """Return severity from alarm_severity_config table, falling back to *default*."""
        return self.alarm_manager._get_alarm_severity(session, alarm_type, default)

    def flush_last_seen_batch(self, session: Session) -> None:
        """
        Issue a single bulk UPDATE for all MAC addresses that only need their
        last_seen timestamp refreshed (no position change).

        Called once per device at the end of save_to_database after the port
        loop.  Replaces N individual ORM UPDATE statements with one
        UPDATE … WHERE mac_address IN (…), which reduces InnoDB row-lock
        contention and eliminates the deadlock pattern triggered when multiple
        parallel sessions flush last_seen changes for the same MAC rows.
        """
        if not self._last_seen_batch:
            return
        mac_list = list(set(self._last_seen_batch))
        self._last_seen_batch = []
        try:
            session.execute(
                text(
                    "UPDATE mac_address_tracking "
                    "SET last_seen = :now "
                    "WHERE mac_address IN :macs"
                ).bindparams(bindparam("macs", expanding=True)),
                {"now": datetime.utcnow(), "macs": mac_list},
            )
        except Exception as exc:
            self.logger.warning(f"flush_last_seen_batch failed ({len(mac_list)} MACs): {exc}")

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
        
        # VLAN-based alarm suppression: skip all change detection for suppressed VLANs
        if current_port_data.vlan_id in _SUPPRESS_ALARM_VLANS:
            self.logger.debug(
                f"Change detection skipped: {device.name} port "
                f"{current_port_data.port_number} is on VLAN "
                f"{current_port_data.vlan_id} (suppress list)"
            )
            self._create_snapshot(session, device, current_port_data)
            return changes

        # Uplink/trunk ports (e.g. Po1-like): only monitor port status (up/down).
        # These backbone ports carry traffic for many devices and must never
        # trigger MAC-change alarms.
        # Check both static list and database-configured uplink ports.
        is_db_uplink = False
        try:
            row = session.execute(
                text("SELECT TOP 1 1 FROM snmp_uplink_ports WHERE device_id = :did AND port_number = :pnum"),
                {"did": device.id, "pnum": current_port_data.port_number}
            ).fetchone()
            is_db_uplink = row is not None
        except Exception as _ue:
            self.logger.debug(
                f"Could not query snmp_uplink_ports for {device.name}:{current_port_data.port_number} "
                f"(table may not exist yet): {_ue}"
            )

        if (device.name, current_port_data.port_number) in _UPLINK_PORTS or is_db_uplink:
            self.logger.debug(
                f"MAC change detection skipped: {device.name} port "
                f"{current_port_data.port_number} is an uplink port (Po1 behaviour)"
            )
            previous_snapshot = self._get_latest_snapshot(
                session, device.id, current_port_data.port_number
            )
            if previous_snapshot:
                status_change = self._detect_status_change(
                    session, device, current_port_data, previous_snapshot
                )
                if status_change:
                    changes.append(status_change)
            self._create_snapshot(session, device, current_port_data)
            return changes

        # Get the previous snapshot for this port
        previous_snapshot = self._get_latest_snapshot(
            session,
            device.id,
            current_port_data.port_number
        )
        
        if not previous_snapshot:
            # First time seeing this port, create initial snapshot.
            # İlk taramada hiç alarm üretme — flood koruması (matris Senaryo 7).
            # Port ilk kez görüldüğünde sadece baseline snapshot oluşturulur;
            # ports.mac'te kayıtlı MAC olsa bile mismatch alarmı üretilmez.
            self._create_snapshot(session, device, current_port_data)
            self.logger.debug(f"Created initial snapshot for {device.name} port {current_port_data.port_number}")
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
        
        # Port status changes (up/down) for regular ports are not recorded in
        # port_change_history — they produce high-frequency noise without
        # actionable value (a port going down also causes MAC=null which is
        # already suppressed above).  Uplink ports still have status tracking
        # via the separate code path above (lines 191-195).
        
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
    ) -> None:
        """Upsert a port snapshot (one row per device+port, updated every poll).

        Uses INSERT ... ON DUPLICATE KEY UPDATE so the table holds exactly one
        current-state row per (device_id, port_number) instead of a new row per
        poll cycle.  This requires the unique key ``uq_ps_device_port`` on
        (device_id, port_number) — added by the
        ``optimize_port_snapshot.sql`` migration.

        If the unique key does not yet exist (old schema) the statement falls
        back to a plain INSERT, preserving backward compatibility.
        """
        session.execute(
            text("""
                MERGE INTO port_snapshot AS target
                USING (SELECT :device_id          AS device_id,
                              :port_number        AS port_number,
                              :snapshot_timestamp AS snapshot_timestamp,
                              :port_name          AS port_name,
                              :port_alias         AS port_alias,
                              :port_description   AS port_description,
                              :admin_status       AS admin_status,
                              :oper_status        AS oper_status,
                              :vlan_id            AS vlan_id,
                              :vlan_name          AS vlan_name,
                              :mac_address        AS mac_address,
                              :mac_addresses      AS mac_addresses) AS src
                ON (target.device_id = src.device_id AND target.port_number = src.port_number)
                WHEN MATCHED THEN
                    UPDATE SET
                        snapshot_timestamp = src.snapshot_timestamp,
                        port_name          = src.port_name,
                        port_alias         = src.port_alias,
                        port_description   = src.port_description,
                        admin_status       = src.admin_status,
                        oper_status        = src.oper_status,
                        vlan_id            = src.vlan_id,
                        vlan_name          = src.vlan_name,
                        mac_address        = IIF(src.oper_status = 'down' AND target.mac_address IS NOT NULL,
                                                 target.mac_address, src.mac_address),
                        mac_addresses      = IIF(src.oper_status = 'down' AND target.mac_addresses IS NOT NULL,
                                                 target.mac_addresses, src.mac_addresses)
                WHEN NOT MATCHED THEN
                    INSERT (device_id, port_number, snapshot_timestamp,
                            port_name, port_alias, port_description,
                            admin_status, oper_status,
                            vlan_id, vlan_name,
                            mac_address, mac_addresses)
                    VALUES (src.device_id, src.port_number, src.snapshot_timestamp,
                            src.port_name, src.port_alias, src.port_description,
                            src.admin_status, src.oper_status,
                            src.vlan_id, src.vlan_name,
                            src.mac_address, src.mac_addresses);
            """),
            {
                "device_id":          device.id,
                "port_number":        port_data.port_number,
                "snapshot_timestamp": datetime.utcnow(),
                "port_name":          port_data.port_name,
                "port_alias":         port_data.port_alias,
                "port_description":   port_data.port_description,
                "admin_status":       port_data.admin_status.value if port_data.admin_status else None,
                "oper_status":        port_data.oper_status.value if port_data.oper_status else None,
                "vlan_id":            port_data.vlan_id,
                "vlan_name":          port_data.vlan_name,
                "mac_address":        port_data.mac_address,
                "mac_addresses":      port_data.mac_addresses,
            },
        )
        # Note: session.expire_all() is intentionally not called here.
        # Each (device_id, port_number) is processed once per session_scope;
        # the session is committed and discarded after all ports are handled.
    
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
        
        # Port is down — MAC fields are null as a side-effect of the link going
        # down, not because the device was physically removed.  Skip all MAC
        # change detection; the preserved snapshot (see _create_snapshot) ensures
        # no false mac_added fires when the port comes back up with the same MAC.
        if current.oper_status and current.oper_status.value == 'down':
            return changes

        # Hub port detection: if the port currently has or previously had multiple
        # MACs, it is connected to a hub/unmanaged switch.  For such ports, MAC
        # churn (devices connecting/disconnecting behind the hub) is completely
        # normal — do NOT create alarms.  Newly-seen MACs are auto-registered so
        # they appear in the UI, and disappeared MACs are silently updated in the
        # tracking table.
        is_hub_port = len(current_macs) > 1 or len(previous_macs) > 1

        # VLAN 70 (AP native VLAN) override: force hub-like MAC-addition suppression.
        # Before the Q-BRIDGE AP trunk filtering was added, AP ports returned ALL WiFi
        # client MACs → many MACs → is_hub_port = True (no alarms).  After filtering,
        # each AP trunk port returns only the physical AP MAC (1 MAC) → is_hub_port = False
        # → new WiFi client MACs trigger false "Cihaz Kaydedildi" alarms.
        # Solution: always treat VLAN 70 ports as hub-like in _detect_mac_changes so
        # that rotating WiFi MACs never create alarms here.  Real AP replacements are
        # still detected by _detect_mac_config_mismatch (runs separately with its own
        # _AP_MAC_MISS_THRESHOLD debounce).
        if current.vlan_id == _AP_NATIVE_VLAN:
            is_hub_port = True
            self.logger.debug(
                f"VLAN 70 AP port {device.name}:{current.port_number}: "
                f"hub-like MAC-addition suppression active (AP trunk filtering "
                f"may have reduced MAC count; real AP change detected via "
                f"_detect_mac_config_mismatch)."
            )

        # Detect new MACs
        new_macs = current_macs - previous_macs
        for mac in new_macs:
            if is_hub_port:
                # Hub port: silently register the new MAC without raising an alarm.
                # Only auto-register for VLANs 150 (JACKPOT) and 1500 (DRGT);
                # other VLANs must not be touched to preserve user-set IP/hostname.
                if current.vlan_id in _AUTO_REGISTER_VLANS:
                    # Prefer VLAN_TYPE_MAP semantic label over raw vlan_name from switch
                    # config (vlan_name could be a raw number like "150" or even mistyped).
                    vlan_label = (
                        VLAN_TYPE_MAP.get(current.vlan_id)
                        or current.vlan_name
                        or (str(current.vlan_id) if current.vlan_id else 'HUB')
                    )
                    self._auto_register_hub_macs(session, {mac}, vlan_label)
                self.logger.debug(
                    f"Hub port {device.name}:{current.port_number}: "
                    f"new MAC {mac} auto-registered, no alarm."
                )
                continue
            change = self._handle_mac_added_or_moved(
                session,
                device,
                current.port_number,
                mac,
                current.vlan_id,
                port_alias=current.port_alias
            )
            if change:
                changes.append(change)

        # Detect removed MACs
        removed_macs = previous_macs - current_macs
        for mac in removed_macs:
            if is_hub_port:
                # Hub port: silently update last_seen via the batch buffer to
                # avoid an individual ORM SELECT + UPDATE per MAC.
                self._last_seen_batch.append(mac)
                self.logger.debug(
                    f"Hub port {device.name}:{current.port_number}: "
                    f"MAC {mac} no longer heard, tracking updated, no alarm."
                )
                continue
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
        vlan_id: Optional[int],
        port_alias: Optional[str] = None
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
            # with_for_update() → SQL Server WITH (UPDLOCK, ROWLOCK): acquires an
            # update lock on the row immediately, preventing the S→X lock upgrade
            # that causes deadlocks when parallel pollers see the same MAC.
            mac_tracking = session.query(MACAddressTracking).with_for_update().filter(
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
        
        # If there's an expected MAC but it doesn't match, this MAC is a client
        # device on an AP uplink port (or similar managed port).  Update MAC
        # tracking silently without raising an alarm.  The real "wrong device"
        # detection is handled by _detect_mac_config_mismatch, which checks
        # whether the registered device's MAC is still present in the full
        # mac_addresses set — so a genuine AP replacement still triggers an alarm.
        if expected_mac and expected_mac != mac_address.upper():
            self.logger.debug(
                f"Non-expected MAC {mac_address} on managed port "
                f"{device.name}:{port_number} (expected {expected_mac}) — "
                f"likely client device, updating tracking without alarm"
            )
            mac_tracking = session.query(MACAddressTracking).with_for_update().filter(
                MACAddressTracking.mac_address == mac_address
            ).first()
            if not mac_tracking:
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
            else:
                mac_tracking.current_device_id = device.id
                mac_tracking.current_port_number = port_number
                mac_tracking.current_vlan_id = vlan_id
                mac_tracking.last_seen = datetime.utcnow()
            return None

        # Check if MAC exists in tracking table
        mac_tracking = session.query(MACAddressTracking).with_for_update().filter(
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
                
                # Check if MAC is returning to its previously tracked port after
                # a port-table reset (UI "Tüm Portları Boşa Çek" action).
                # When the ports table is cleared the registered_location check
                # above returns None, but MAC tracking still remembers where the
                # device was.  If it's coming back to the SAME port it left from
                # and it currently has no tracked location (current_device_id is
                # None), suppress alarm ONLY if the MAC is already registered in
                # Device Import (mac_device_registry).  If it is NOT registered,
                # fire a mac_added alarm so the admin can register it.
                if (mac_tracking.current_device_id is None and
                        mac_tracking.previous_device_id == device.id and
                        mac_tracking.previous_port_number == port_number):
                    if self._is_mac_in_device_registry(session, mac_address):
                        self.logger.debug(
                            f"MAC {mac_address} returning to its previous port "
                            f"{device.name}:{port_number} after port reset "
                            f"(registered in Device Import). No alarm needed."
                        )
                        mac_tracking.current_device_id = device.id
                        mac_tracking.current_port_number = port_number
                        mac_tracking.current_vlan_id = vlan_id
                        mac_tracking.last_seen = datetime.utcnow()
                        return None
                    else:
                        # MAC is NOT in Device Import — create mac_added alarm so
                        # the admin can register it in the system.
                        self.logger.info(
                            f"MAC {mac_address} returned to {device.name}:{port_number} "
                            f"but is NOT registered in Device Import. Creating alarm."
                        )
                        mac_tracking.current_device_id = device.id
                        mac_tracking.current_port_number = port_number
                        mac_tracking.current_vlan_id = vlan_id
                        mac_tracking.last_seen = datetime.utcnow()
                        return self._record_mac_added(
                            session, device, port_number, mac_address, vlan_id,
                            port_alias=port_alias
                        )

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
                    old_vlan_id=mac_tracking.current_vlan_id,
                    port_alias=port_alias
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
                # Same location — queue last_seen update into the batch buffer
                # so all such MACs for this device are refreshed with ONE SQL
                # UPDATE instead of N individual ORM dirty-object UPDATEs.
                self._last_seen_batch.append(mac_address)
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
            
            # Rule B3: No expected MAC for this port and tracking shows no previous
            # history on this port (tracking_same_port == false).
            # Check mac_device_registry to decide whether to alarm:
            #   registry_known == true  → device is already inventoried; no alarm,
            #                             only update tracking silently
            #   registry_known == false → genuinely new/unknown device → mac_added
            if self._is_mac_in_device_registry(session, mac_address):
                self.logger.debug(
                    f"New MAC {mac_address} on {device.name} port {port_number} "
                    f"is in Device Import (registry_known). Tracking updated, no alarm."
                )
                return None

            # Record as new MAC (only if not on registered port and not in registry)
            change = self._record_mac_added(
                session,
                device,
                port_number,
                mac_address,
                vlan_id,
                port_alias=port_alias
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
        mac_tracking = session.query(MACAddressTracking).with_for_update().filter(
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
                SELECT TOP 1 p.connected_to 
                FROM ports p
                JOIN switches s ON p.switch_id = s.id
                WHERE s.name = :device_name AND p.port_no = :port_number
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
                SELECT TOP 1 s.name, p.port_no, p.device, p.connected_to
                FROM ports p
                JOIN switches s ON p.switch_id = s.id
                WHERE UPPER(p.mac) = :mac_address
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
    
    def _is_mac_in_device_registry(self, session: Session, mac_address: str) -> bool:
        """Return True if *mac_address* exists in mac_device_registry.

        This table is populated by Device Import (Excel/domain/manual) and by
        admin UI manual registration.  Entries with source='snmp_hub_auto' are
        also counted — they indicate the system already knows about this device.
        """
        try:
            row = session.execute(
                text("SELECT TOP 1 1 FROM mac_device_registry WHERE mac_address = :mac"),
                {"mac": mac_address}
            ).fetchone()
            return row is not None
        except Exception as exc:
            self.logger.debug(f"Could not query mac_device_registry for {mac_address}: {exc}")
            return False

    def _get_port_alias_from_snapshot(
        self,
        session: Session,
        device_id: int,
        port_number: int
    ) -> Optional[str]:
        """Return the port_alias stored in port_snapshot for a given device+port, or None."""
        try:
            row = session.execute(
                text(
                    "SELECT TOP 1 port_alias FROM port_snapshot "
                    "WHERE device_id = :did AND port_number = :pnum"
                ),
                {"did": device_id, "pnum": port_number}
            ).fetchone()
            return row[0] if row and row[0] else None
        except Exception as exc:
            self.logger.debug(f"Could not query port_snapshot for alias: {exc}")
            return None

    @staticmethod
    def _mac_move_conn_label(alias: Optional[str], reg_ip: Optional[str]) -> str:
        """Return a human-readable connection label for one side of a MAC move.

        Examples:
          alias="DRGT",  reg_ip="172.18.1.1" → "DRGT(172.18.1.1)"
          alias="LAN",   reg_ip=None          → "LAN"
          alias=None,    reg_ip=None          → "Kayıtlı değil"
        """
        if alias:
            return f"{alias}({reg_ip})" if reg_ip else alias
        return "Kayıtlı değil"

    @staticmethod
    def _port_context_suffix(vlan_id: Optional[int], port_alias: Optional[str]) -> str:
        """Build a human-readable context string to append to alarm messages.

        Examples:
          vlan_id=1500, port_alias="DRGT" → ". VLAN 1500, Mevcut Bağlantı DRGT."
          vlan_id=1500, port_alias=None   → ". VLAN 1500."
          vlan_id=None,  port_alias="LAN" → ". Mevcut Bağlantı LAN."
          vlan_id=None,  port_alias=None  → ""
        """
        parts = []
        if vlan_id:
            parts.append(f"VLAN {vlan_id}")
        if port_alias:
            parts.append(f"Mevcut Bağlantı {port_alias}")
        return (". " + ", ".join(parts) + ".") if parts else ""

    def _lookup_mac_in_registry(self, session: Session, mac_address: str):
        """Return (ip_address, device_name) tuple from mac_device_registry for *mac_address*.

        Returns None when the MAC is not found or an error occurs.  Used to enrich
        mac_added alarm messages with the human-readable Device Import label so the
        admin immediately knows which registered device appeared on the wrong port.
        """
        try:
            row = session.execute(
                text("SELECT TOP 1 ip_address, device_name FROM mac_device_registry WHERE mac_address = :mac"),
                {"mac": mac_address}
            ).fetchone()
            if row is not None:
                return (row[0], row[1])
            return None
        except Exception as exc:
            self.logger.debug(f"Could not lookup mac_device_registry for {mac_address}: {exc}")
            return None

    def _auto_register_hub_macs(
        self,
        session: Session,
        macs,
        vlan_label: str
    ) -> None:
        """Auto-register hub-port MACs in mac_device_registry without creating alarms.

        Called when a new MAC appears on a multi-MAC (hub) port so that the device
        becomes visible in the UI immediately.  Uses the VLAN label as both the IP
        placeholder and the device-name (consistent with autosync_service behaviour).

        Entries that were previously set via Excel import ('excel'), manual
        entry ('manual'), or any other non-auto source are NOT overwritten —
        only entries with source='snmp_hub_auto' (previously auto-registered)
        are updated in-place.
        """
        for mac in macs:
            try:
                hex_only = re.sub(r'[^0-9A-Fa-f]', '', mac).upper()
                if len(hex_only) != 12:
                    continue
                mac_norm = ':'.join(hex_only[i:i+2] for i in range(0, 12, 2))
                session.execute(
                    text("""
                        MERGE INTO mac_device_registry AS target
                        USING (SELECT :mac  AS mac_address,
                                      :ip   AS ip_address,
                                      :name AS device_name) AS src
                        ON target.mac_address = src.mac_address
                        WHEN MATCHED THEN
                            UPDATE SET
                                ip_address  = IIF(target.source = 'snmp_hub_auto', src.ip_address,  target.ip_address),
                                device_name = IIF(target.source = 'snmp_hub_auto', src.device_name, target.device_name),
                                updated_at  = GETDATE()
                        WHEN NOT MATCHED THEN
                            INSERT (mac_address, ip_address, device_name, source, created_by)
                            VALUES (src.mac_address, src.ip_address, src.device_name, 'snmp_hub_auto', 'snmp_worker');
                    """),
                    {"mac": mac_norm, "ip": vlan_label, "name": vlan_label},
                )
                self.logger.debug(
                    f"Hub MAC auto-registered (no alarm): {mac_norm} → {vlan_label}"
                )
            except Exception as e:
                self.logger.warning(
                    f"Hub MAC auto-register failed for {mac}: {e}"
                )

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
                SELECT TOP 1 UPPER(p.mac)
                FROM ports p
                JOIN switches s ON p.switch_id = s.id
                WHERE s.name = :device_name 
                AND p.port_no = :port_number
                AND p.mac IS NOT NULL
                AND p.mac != ''
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
        old_vlan_id: Optional[int] = None,
        port_alias: Optional[str] = None
    ) -> PortChangeHistory:
        """Record a MAC address movement and create alarm."""

        # Farklı VLAN bağlamları arası MAC hareketi → CBS350/C9200L FDB artifact.
        # Aynı switch üzerinde farklı VLAN FDB'lerini SNMP ile sorguladığımızda
        # aynı MAC, farklı VLAN tablolarında farklı portlarda görünebilir.
        # Bu fiziksel bir hareket değil; VLAN FDB'nin doğal davranışıdır.
        # Alarm üretmeden sadece geçmiş kaydı oluştur.
        if (
            old_vlan_id is not None
            and vlan_id is not None
            and old_vlan_id != vlan_id
            and old_port is not None
            and old_device is not None
            and old_device.id == new_device.id  # Aynı switch
        ):
            self.logger.debug(
                f"MAC {mac_address}: VLAN bağlamı değişti "
                f"(port {old_port} VLAN {old_vlan_id} → port {new_port} VLAN {vlan_id}) "
                f"cihaz: {new_device.name} – VLAN FDB artifact, alarm yok."
            )
            change = PortChangeHistory(
                device_id=new_device.id,
                port_number=new_port,
                change_type=ChangeType.MAC_MOVED,
                change_timestamp=datetime.utcnow(),
                old_mac_address=mac_address,
                new_mac_address=mac_address,
                from_device_id=new_device.id,
                from_port_number=old_port,
                to_device_id=new_device.id,
                to_port_number=new_port,
                new_vlan_id=vlan_id,
                change_details=(
                    f"VLAN FDB artifact (alarm yok): MAC {mac_address} "
                    f"VLAN {old_vlan_id}→{vlan_id} port {old_port}→{new_port} "
                    f"cihaz: {new_device.name}"
                )
            )
            session.add(change)
            return change

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
        
        # Look up Device Import registry entry for the moved MAC
        _reg_info = self._lookup_mac_in_registry(session, mac_address)
        _reg_ip = _reg_info[0] if _reg_info else None

        # Resolve port aliases for both sides
        old_alias: Optional[str] = None
        if old_device and old_port is not None:
            old_alias = self._get_port_alias_from_snapshot(session, old_device.id, old_port)

        # Build human-readable connection labels for Device-A and Device-B
        old_conn = self._mac_move_conn_label(old_alias, _reg_ip)
        new_conn = self._mac_move_conn_label(port_alias, _reg_ip)

        # Build the change_details message in the requested format:
        # "MAC xx moved from Device-A port Y to Device-B port Z VLAN 1500,
        #  Device-A Mevcut Bağlantı DRGT(172.18....). Device-B Mevcut Bağlantı Osman(172.18....)."
        change_details = (
            f"MAC {mac_address} moved from {old_device_name} port {old_port_str} "
            f"to {new_device.name} port {new_port}"
        )
        if vlan_id:
            change_details += f" VLAN {vlan_id}"
        change_details += (
            f", {old_device_name} Mevcut Bağlantı {old_conn}."
            f" {new_device.name} Mevcut Bağlantı {new_conn}."
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
            self._alarm_severity(session, "mac_moved", "HIGH"),
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
                mac_move_data = {
                    "old_device_name": old_device_name,
                    "old_port": old_port_str,
                    "new_device_name": new_device.name,
                    "new_port": str(new_port),
                    "old_conn": old_conn,
                    "new_conn": new_conn,
                    "vlan_id": vlan_id,
                    "mac_address": mac_address,
                }
                self.alarm_manager._send_notifications(
                    new_device,
                    "mac_moved",
                    alarm.severity if alarm.severity else "HIGH",
                    change_details,
                    port_number=new_port,
                    port_name=f"Port {new_port}",
                    session=session,
                    extra_data=mac_move_data
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
        vlan_id: Optional[int],
        port_alias: Optional[str] = None
    ) -> PortChangeHistory:
        """Record a new MAC address on a port."""

        change_details = f"New MAC {mac_address} detected on {device.name} port {port_number}"
        # Build enriched "Mevcut Bağlantı" using Device Import info when available.
        _reg_info = self._lookup_mac_in_registry(session, mac_address)
        if _reg_info:
            _reg_ip, _reg_name = _reg_info
            _reg_parts = [p for p in [_reg_ip, _reg_name] if p]
            _mevcut_label = (' '.join(_reg_parts) + ' olarak kayıtlı') if _reg_parts else port_alias
        else:
            _mevcut_label = port_alias
        change_details += self._port_context_suffix(vlan_id, _mevcut_label)

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

        # WiFi SSID VLANs broadcast by an AP alongside its management VLAN 70.
        # When VLAN 70 (AP) is present on a port, the other VLANs are
        # virtual wireless-client VLANs — not a real physical reconfiguration.
        # Suppress VLAN change alarms for any transition involving VLAN 70 ↔
        # any WiFi SSID VLAN, or between two WiFi SSID VLANs.
        # WiFi SSID VLANs: 30 (GUEST), 40 (VIP), 50 (DEVICE), 130 (IPTV),
        # 140 (SANTRAL), 254 (SERVER).
        _AP_VLAN = 70
        _WIFI_SSID_VLANS = {30, 40, 50, 130, 140, 254}

        def _is_wifi_virtual_transition(old_v, new_v):
            return (
                (old_v == _AP_VLAN and new_v in _WIFI_SSID_VLANS) or
                (new_v == _AP_VLAN and old_v in _WIFI_SSID_VLANS) or
                (old_v in _WIFI_SSID_VLANS and new_v in _WIFI_SSID_VLANS)
            )

        def _is_ap_vlan_name(name: str) -> bool:
            """Detect AP-related VLAN names using a naming convention.

            Ports connected to Access Points are often assigned VLANs whose
            names embed the base VLAN in parentheses, e.g.:
              "AP(SANTRAL)"   – the AP variant of the SANTRAL VLAN
              "SANTRAL(AP)"   – the SANTRAL assignment for an AP port
            Any VLAN whose name contains '(AP)' or starts with 'AP(' (case-
            insensitive) is considered an AP-virtual VLAN.  Plain 'AP' is also
            recognized as the dedicated AP management VLAN.
            """
            if not name:
                return False
            u = name.strip().upper()
            return u == "AP" or "(AP)" in u or u.startswith("AP(")

        def _is_ap_vlan_oscillation(old_name, new_name):
            """Return True when both VLAN names represent the same AP/device port.

            Covers patterns like:
              SANTRAL  ↔  AP(SANTRAL)   – same physical VLAN, AP variant
              AP       ↔  AP(SANTRAL)   – AP management ↔ AP-assigned
              AP       ↔  SANTRAL(AP)
            One side must be an AP-related name *and* the other name must appear
            as a substring of the AP-side name (or vice versa), confirming they
            are two views of the same port rather than a genuine VLAN move.
            """
            if not old_name or not new_name:
                return False
            old_u = old_name.strip().upper()
            new_u = new_name.strip().upper()
            # Use already-uppercased strings for AP-name detection to avoid
            # redundant case-conversion inside _is_ap_vlan_name.
            if _is_ap_vlan_name(old_u) or _is_ap_vlan_name(new_u):
                # Check substring relationship: "SANTRAL" in "AP(SANTRAL)"
                if old_u in new_u or new_u in old_u:
                    return True
            return False

        # Only fire a VLAN-changed alarm when BOTH the old and new VLANs are
        # meaningful (>1, not None).  If the new VLAN becomes None/0/1 the port
        # lost its VLAN info (usually because it went down), which is NOT a
        # meaningful VLAN configuration change.
        #
        # VLAN 70 is the dedicated AP management VLAN.  Any transition involving
        # VLAN 70 ↔ a WiFi SSID VLAN (30/40/50/130/140/254) is AP oscillation
        # regardless of whether a MAC is registered on the port — AP uplink ports
        # that have not yet had a device registered still exhibit this oscillation.
        # Suppressing unconditionally avoids false alarms that confuse staff.

        if (not _is_default_vlan(previous.vlan_id)
                and not _is_default_vlan(current.vlan_id)
                and current.vlan_id != previous.vlan_id
                and not _is_wifi_virtual_transition(previous.vlan_id, current.vlan_id)):

            old_vlan_label = previous.vlan_name or str(previous.vlan_id)
            new_vlan_label = current.vlan_name or str(current.vlan_id)

            # Suppress AP-port VLAN oscillation.  AP-connected ports frequently
            # report alternating VLANs because the switch sees traffic from both
            # the AP device VLAN and the wireless-client VLAN.  When the VLAN
            # names follow the "(AP)" convention (e.g. SANTRAL ↔ AP(SANTRAL)),
            # this is NOT a real reconfiguration — suppress unconditionally.
            if _is_ap_vlan_oscillation(previous.vlan_name, current.vlan_name):
                self.logger.debug(
                    f"VLAN alarm suppressed (AP-port oscillation): "
                    f"{device.name} port {current.port_number} "
                    f"{old_vlan_label} → {new_vlan_label}"
                )
                return None

            change_details = (
                f"{device.name} port {current.port_number} VLAN değişti: "
                f"{old_vlan_label} → {new_vlan_label}"
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
                self._alarm_severity(session, "vlan_changed", "MEDIUM"),
                f"VLAN değişti: Port {current.port_number}",
                change_details,
                port_number=current.port_number
            )
            
            if alarm:
                change.alarm_created = True
                change.alarm_id = alarm.id
                alarm.old_value = old_vlan_label
                alarm.new_value = new_vlan_label
                if is_new:
                    self.alarm_manager._send_notifications(
                        device,
                        "vlan_changed",
                        alarm.severity if alarm.severity else "MEDIUM",
                        change_details,
                        port_number=current.port_number,
                        port_name=f"Port {current.port_number}",
                        session=session
                    )
                    alarm.notification_sent = True
                    alarm.last_notification_sent = datetime.utcnow()
            
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
                self._alarm_severity(session, "description_changed", "LOW"),
                f"Açıklama değişti: Port {current.port_number}",
                change_details,
                port_number=current.port_number
            )
            
            if alarm:
                change.alarm_created = True
                change.alarm_id = alarm.id
                alarm.old_value = previous_desc or '(empty)'
                alarm.new_value = current_desc or '(empty)'
                if is_new:
                    self.alarm_manager._send_notifications(
                        device,
                        "description_changed",
                        alarm.severity if alarm.severity else "MEDIUM",
                        change_details,
                        port_number=current.port_number,
                        port_name=f"Port {current.port_number}",
                        session=session
                    )
                    alarm.notification_sent = True
                    alarm.last_notification_sent = datetime.utcnow()
            
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
        
        # Per-port trace log (DEBUG only — do NOT use INFO or this fires for
        # every port on every device every cycle, flooding the log file).
        self.logger.debug("MAC check - %s Port %s: '%s' → '%s'",
                          device.name, current.port_number, previous_mac, current_mac)
        
        if current_mac != previous_mac:
            both_have_mac = bool(previous_mac) and bool(current_mac)
            
            if not both_have_mac:
                # One or both MACs are empty — this is a device connect/disconnect
                # event, not a device swap.  _detect_mac_changes already writes the
                # mac_added / mac_removed history row for this transition; writing
                # a second row here would create duplicates.
                if not previous_mac and current_mac:
                    self.logger.debug(
                        f"{device.name} port {current.port_number}: "
                        f"cihaz bağlandı (empty → {current_mac}), alarm yok"
                    )
                elif previous_mac and not current_mac:
                    self.logger.debug(
                        f"{device.name} port {current.port_number}: "
                        f"cihaz ayrıldı ({previous_mac} → empty), alarm yok"
                    )
                return None

            # Ports with a registered expected MAC are managed device ports (APs,
            # servers, etc.).  Snapshot-to-snapshot single-MAC comparison is
            # suppressed for such ports because:
            #   - _detect_mac_config_mismatch covers the "wrong device" case using
            #     the full mac_addresses JSON set (which includes all FDB MACs).
            #   - AP uplink ports have rotating wireless-client MACs — the "first
            #     MAC in FDB" oscillates between the AP's own MAC and client MACs,
            #     generating false "MAC changed" alarms on every poll cycle.
            expected_mac = self._get_expected_mac_for_port(session, device, current.port_number)
            if expected_mac:
                self.logger.debug(
                    f"Skipping snapshot MAC change alarm on {device.name} port "
                    f"{current.port_number} (registered MAC present — AP/managed "
                    f"port, client rotation expected)"
                )
                return None

            # Hub port detection: if either the current or previous snapshot has
            # more than one MAC the port is connected to an unmanaged switch.
            # The "first MAC in FDB" rotates between connected devices on every poll
            # cycle so snapshot-to-snapshot comparison produces constant false alarms.
            # Suppress without creating a change record — _detect_mac_config_mismatch
            # already handles the multi-MAC expected case via set comparison.
            current_macs_snap = self._parse_mac_addresses(
                current.mac_address, current.mac_addresses
            )
            previous_macs_snap = self._parse_mac_addresses(
                previous.mac_address, previous.mac_addresses
            )
            if len(current_macs_snap) > 1 or len(previous_macs_snap) > 1:
                self.logger.debug(
                    f"Skipping snapshot MAC change alarm on {device.name} port "
                    f"{current.port_number} (hub port: current {len(current_macs_snap)} MACs, "
                    f"previous {len(previous_macs_snap)} MACs — FDB rotation expected)"
                )
                return None

            # Both MACs are non-empty - this is a device swap, create alarm!
            change_details = (
                f"{device.name} port {current.port_number} MAC adresi değişti: "
                f"'{previous_mac}' → '{current_mac}'"
            )
            
            self.logger.warning(change_details)
            
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
            
            # Create alarm for MAC address change
            alarm, is_new = self.db_manager.get_or_create_alarm(
                session,
                device,
                "mac_moved",
                self._alarm_severity(session, "mac_moved", "HIGH"),  # High severity like other MAC alarms
                f"MAC adresi değişti: Port {current.port_number}",
                change_details,
                port_number=current.port_number,
                mac_address=current_mac or None
            )
            
            if alarm:
                change.alarm_created = True
                change.alarm_id = alarm.id
                alarm.old_value = previous_mac or '(empty)'
                alarm.new_value = current_mac or '(empty)'
                
                # Send notifications for new alarms
                if is_new:
                    self.alarm_manager._send_notifications(
                        device,
                        "mac_moved",
                        alarm.severity if alarm.severity else "HIGH",
                        change_details,
                        port_number=current.port_number,
                        port_name=f"Port {current.port_number}",
                        session=session
                    )
                    alarm.notification_sent = True
                    alarm.last_notification_sent = datetime.utcnow()
            else:
                self.logger.error(
                    f"MAC değişiklik alarmı oluşturulamadı: "
                    f"{device.name} port {current.port_number}"
                )
            
            return change
        
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
        
        # Get the expected/configured MAC from ports table.
        # For hub ports the ports.mac column stores a comma-separated list of all
        # known MACs (e.g. "MAC1,MAC2,...").  We normalise this into a set of
        # individual uppercase MACs so we can do a proper set comparison against
        # what SNMP currently sees.
        expected_mac_raw = self._get_expected_mac_for_port(session, device, current.port_number)

        self.logger.debug(
            f"MAC config check for {device.name} port {current.port_number}: "
            f"expected_raw={expected_mac_raw}"
        )

        # Normalise expected MACs: strip whitespace, filter empty strings.
        # Works for both a single MAC ("AA:BB:CC:DD:EE:FF") and a comma-separated
        # list ("AA:BB:CC:DD:EE:FF,11:22:33:44:55:66,...").
        if expected_mac_raw:
            expected_macs_set: set = {
                m.strip().upper() for m in expected_mac_raw.split(',') if m.strip()
            }
        else:
            expected_macs_set = set()

        # Convenience alias for the single-MAC case (backwards compat with
        # tracking / grace-period queries below).
        expected_mac = expected_mac_raw  # may still be a comma-separated string

        # If no expected MAC is configured but SNMP found a MAC on this port,
        # fire a "mac_added" alarm so the user knows a MAC appeared on an
        # unconfigured port (or on a port whose MAC was intentionally deleted).
        # Only fire when we have a previous snapshot (not on first scan) to
        # avoid alarm floods during initial setup.
        if not expected_macs_set:
            current_mac_detected = (current.mac_address or '').upper().strip()
            if previous is not None and current_mac_detected:
                # AP native VLAN (VLAN 70): MAC-addition suppression mirrors _detect_mac_changes.
                # WiFi client MACs appear on AP trunk ports naturally; they must never
                # trigger mac_added alarms here even when ports.mac is not yet populated.
                if current.vlan_id == _AP_NATIVE_VLAN:
                    self.logger.debug(
                        f"MAC {current_mac_detected} on VLAN 70 AP port "
                        f"{device.name}:{current.port_number} with no expected MAC — "
                        f"suppressed (AP trunk port, mac_added alarm not raised)."
                    )
                    return None

                # Scenario 1: Port was reset via UI (ports.mac cleared) but the
                # device is physically still there — the previous SNMP snapshot
                # already has this exact MAC.  The MAC didn't change; only the
                # ports-table registration was wiped.  Suppress the alarm.
                previous_macs_snap = self._parse_mac_addresses(
                    previous.mac_address,
                    previous.mac_addresses
                )
                if current_mac_detected in previous_macs_snap:
                    self.logger.debug(
                        f"MAC {current_mac_detected} was already present in previous "
                        f"snapshot for {device.name} port {current.port_number}. "
                        f"Port was reset (ports table cleared) but MAC is unchanged. "
                        f"No alarm needed."
                    )
                    return None

                # Rule B2 / B3: Port was reset and the device was briefly
                # disconnected (empty SNMP snapshot), but the SAME MAC is now
                # returning to the SAME port.  MACAddressTracking records this.
                #
                # Decision priority (per MAC alarm spec):
                #   same_port_current: MAC was never actually absent — tracking already
                #     shows it on this port.  Always suppress (this is effectively B1).
                #   same_port_previous: Port was briefly empty; MAC is returning.
                #     B2 rule — suppress only if the MAC is known in mac_device_registry;
                #     otherwise create a mac_added alarm so the admin can register it.
                mac_tracking_check = session.query(MACAddressTracking).with_for_update().filter(
                    MACAddressTracking.mac_address == current_mac_detected
                ).first()
                if mac_tracking_check:
                    same_port_current = (
                        mac_tracking_check.current_device_id == device.id and
                        mac_tracking_check.current_port_number == current.port_number
                    )
                    same_port_previous = (
                        mac_tracking_check.previous_device_id == device.id and
                        mac_tracking_check.previous_port_number == current.port_number and
                        mac_tracking_check.current_device_id is None
                    )
                    # Restore tracking in all branches first
                    if same_port_current or same_port_previous:
                        mac_tracking_check.current_device_id = device.id
                        mac_tracking_check.current_port_number = current.port_number
                        mac_tracking_check.last_seen = datetime.utcnow()

                    if same_port_current:
                        # B1-equivalent: MAC is already tracked here — no alarm
                        self.logger.debug(
                            f"MAC {current_mac_detected} already tracked on "
                            f"{device.name}:{current.port_number}. No alarm needed."
                        )
                        return None

                    if same_port_previous:
                        # B2: MAC returned to same port after brief absence.
                        # Suppress only if the device is known in mac_device_registry.
                        if self._is_mac_in_device_registry(session, current_mac_detected):
                            self.logger.debug(
                                f"MAC {current_mac_detected} returned to "
                                f"{device.name}:{current.port_number} after port reset "
                                f"(registered in Device Import). No alarm needed."
                            )
                            return None
                        # Unknown device returning after port reset → mac_added
                        self.logger.info(
                            f"MAC {current_mac_detected} returned to "
                            f"{device.name}:{current.port_number} after port reset "
                            f"but is NOT in Device Import. Creating mac_added alarm."
                        )
                        # Fall through to mac_added creation below

                change_details = (
                    f"{device.name} port {current.port_number} yeni MAC adresi tespit edildi: "
                    f"'{current_mac_detected}' (kayıtlı MAC adresi yoktu)"
                )
                # Build enriched "Mevcut Bağlantı" using Device Import info (same logic as MAC mismatch).
                registry_info = self._lookup_mac_in_registry(session, current_mac_detected)
                if registry_info:
                    _reg_ip, _reg_name = registry_info
                    _reg_parts = [p for p in [_reg_ip, _reg_name] if p]
                    _mevcut_label = (' '.join(_reg_parts) + ' olarak kayıtlı') if _reg_parts else current.port_alias
                else:
                    _mevcut_label = current.port_alias
                change_details += self._port_context_suffix(current.vlan_id, _mevcut_label)
                self.logger.warning(
                    f"MAC eklendi: {device.name} port {current.port_number} → {current_mac_detected}"
                )
                change = PortChangeHistory(
                    device_id=device.id,
                    port_number=current.port_number,
                    change_type=ChangeType.MAC_ADDED,
                    change_timestamp=datetime.utcnow(),
                    new_mac_address=current_mac_detected,
                    change_details=change_details
                )
                session.add(change)
                session.flush()

                alarm, is_new = self.db_manager.get_or_create_alarm(
                    session,
                    device,
                    "mac_added",
                    self._alarm_severity(session, "mac_added", "MEDIUM"),
                    f"MAC adresi eklendi: Port {current.port_number}",
                    change_details,
                    port_number=current.port_number,
                    mac_address=current_mac_detected,
                )
                if alarm:
                    change.alarm_created = True
                    change.alarm_id = alarm.id
                    alarm.new_value = current_mac_detected
                    if is_new:
                        self.alarm_manager._send_notifications(
                            device, "mac_added", alarm.severity if alarm.severity else "MEDIUM", change_details,
                            port_number=current.port_number,
                            port_name=f"Port {current.port_number}",
                            session=session
                        )
                        alarm.notification_sent = True
                        alarm.last_notification_sent = datetime.utcnow()
                return change
            self.logger.debug(f"No expected MAC configured and no MAC detected for port {current.port_number}, skipping mismatch check")
            return None

        # Get current MAC from SNMP data
        current_macs = self._parse_mac_addresses(
            current.mac_address,
            current.mac_addresses
        )

        self.logger.debug(
            f"Current MACs on port {current.port_number}: {current_macs}"
        )

        # --- Hub / multi-MAC port: check whether expected set == current set ---
        # The ports.mac column stores the last-known full MAC list for hub ports.
        # Compare normalised sets; if they are equal (regardless of ordering or
        # whitespace) there is NO mismatch — do NOT alarm.
        if len(expected_macs_set) > 1:
            # Multi-MAC expected (hub port): all expected MACs must be present.
            # Update last_seen for each expected MAC that is currently visible.
            for emac in expected_macs_set:
                if emac in current_macs:
                    mac_tracking = session.query(MACAddressTracking).with_for_update().filter(
                        MACAddressTracking.mac_address == emac
                    ).first()
                    if mac_tracking:
                        age_secs = (
                            (datetime.utcnow() - mac_tracking.last_seen).total_seconds()
                            if mac_tracking.last_seen else None
                        )
                        if age_secs is None or age_secs > 300:
                            mac_tracking.last_seen = datetime.utcnow()
                            mac_tracking.current_device_id = device.id
                            mac_tracking.current_port_number = current.port_number

            missing_macs = expected_macs_set - current_macs
            added_macs = current_macs - expected_macs_set

            if not missing_macs and not added_macs:
                # Sets are identical — no alarm (fixes whitespace false-positive)
                self.logger.debug(
                    f"Hub port {device.name}:{current.port_number}: "
                    f"expected MACs == current MACs (set comparison). No alarm."
                )
                return None

            if not current_macs:
                # Port empty — silent (device disconnected or FDB flushed)
                self.logger.info(
                    f"Hub port {device.name}:{current.port_number} has no MACs "
                    f"(port empty). Expected {len(expected_macs_set)} MACs. Skipping alarm."
                )
                return None

            # ── Hub port alarm suppression ────────────────────────────────────
            # For ALL hub ports (multi-MAC expected), MAC churn is normal:
            # devices connect/disconnect frequently.  Newly-seen MACs are
            # auto-registered in mac_device_registry ONLY for VLANs 150
            # (JACKPOT) and 1500 (DRGT) so they appear in the UI.
            # Other VLANs (70/AP, 50/DEVICE, 80/KAMERA, etc.) are not touched
            # to avoid overwriting IP/hostname data set via Excel or manually.
            # Neither added nor missing MACs generate alarms.
            if added_macs and current.vlan_id in _AUTO_REGISTER_VLANS:
                # Prefer VLAN_TYPE_MAP semantic label over raw vlan_name from switch config.
                vlan_label = (
                    VLAN_TYPE_MAP.get(current.vlan_id)
                    or current.vlan_name
                    or (str(current.vlan_id) if current.vlan_id else 'HUB')
                )
                self._auto_register_hub_macs(session, added_macs, vlan_label)
            self.logger.debug(
                f"Hub port {device.name}:{current.port_number}: "
                f"suppressing MAC-change alarms. "
                f"missing={missing_macs}, added={added_macs}"
            )
            return None

        # --- Single-MAC expected (standard device port) ---
        # expected_macs_set has exactly one element.
        single_expected = next(iter(expected_macs_set))

        # Check if expected MAC is present
        if single_expected in current_macs:
            # Expected MAC found - no mismatch.
            # Keep last_seen up-to-date so the grace-period logic below works
            # correctly. Only write to DB if last_seen is stale (> 5 min) to
            # avoid an unnecessary write on every poll cycle.
            mac_tracking = session.query(MACAddressTracking).with_for_update().filter(
                MACAddressTracking.mac_address == single_expected
            ).first()
            if mac_tracking:
                age_secs = (datetime.utcnow() - mac_tracking.last_seen).total_seconds() \
                           if mac_tracking.last_seen else None
                if age_secs is None or age_secs > 300:  # update at most once per 5 min
                    mac_tracking.last_seen = datetime.utcnow()
                    mac_tracking.current_device_id = device.id
                    mac_tracking.current_port_number = current.port_number
            # VLAN 70 (AP native VLAN): reset the per-port miss counter because the
            # physical AP MAC is visible — the port is operating normally.
            if current.vlan_id == _AP_NATIVE_VLAN:
                port_key = (device.name, current.port_number)
                if self._ap_mac_miss_counts.get(port_key, 0) > 0:
                    self.logger.debug(
                        f"VLAN 70 AP port {device.name}:{current.port_number}: "
                        f"expected MAC {single_expected} re-appeared — miss counter reset."
                    )
                    self._ap_mac_miss_counts[port_key] = 0
            self.logger.debug(
                f"Expected MAC {single_expected} found on port {current.port_number} - no alarm"
            )
            return None

        # Mismatch detected! Expected MAC not found on port
        # Uyuşmazlık tespit edildi! Beklenen MAC port'ta bulunamadı

        # Determine what MAC is actually there
        actual_mac = current.mac_address.upper() if current.mac_address else None

        # Check if port has no MAC (device disconnected)
        if not current_macs:
            # Port is empty but we expected a MAC
            # Check if we already have a tracking entry for this port
            mac_tracking = session.query(MACAddressTracking).filter(
                MACAddressTracking.current_device_id == device.id,
                MACAddressTracking.current_port_number == current.port_number,
                MACAddressTracking.mac_address == single_expected
            ).first()

            if mac_tracking and mac_tracking.last_seen:
                self.logger.info(
                    f"Port {current.port_number} has no MAC address (device disconnected). "
                    f"Expected MAC '{single_expected}' but port is empty. "
                    f"MAC was last seen at {mac_tracking.last_seen}. "
                    f"Skipping repeated 'no MAC' alarm."
                )
                return None

            self.logger.info(
                f"Port {current.port_number} has no MAC address. Expected MAC '{single_expected}' "
                f"but port is empty and MAC was never tracked. Skipping alarm."
            )
            return None

        # Port has MAC(s) but not the expected one.
        # Before alarming, apply grace-period logic.
        #
        # Hub port detection: mirrors _detect_mac_changes logic.
        # A port is treated as a hub if it CURRENTLY has OR PREVIOUSLY HAD > 1 MAC.
        # Using the previous snapshot catches the FDB-aging case where a hub port
        # temporarily shows only 1 MAC (below _AP_PORT_MAC_COUNT_THRESHOLD) between
        # poll cycles because some devices' entries aged out of the FDB table.
        previous_macs_for_hub = self._parse_mac_addresses(
            previous.mac_address if previous else None,
            previous.mac_addresses if previous else None,
        )
        is_hub_port_actual = len(current_macs) > 1 or len(previous_macs_for_hub) > 1

        # A port is treated as a trunk/AP port if:
        #   a) it is a hub/unmanaged-switch port (current or previous snapshot), OR
        #   b) it has no VLAN assignment AND more than one MAC (classic trunk), OR
        #   c) it has _AP_PORT_MAC_COUNT_THRESHOLD or more distinct MACs regardless
        #      of VLAN — a port with 4+ MACs is served by an AP or a downstream
        #      switch even when the SNMP agent reports a VLAN for it.  Firing a
        #      MAC-mismatch alarm on such a port produces constant false positives
        #      because the wireless clients seen in FDB are not the registered MAC.
        # Additionally, if the current VLAN is a WiFi companion VLAN (30/40/50/130/
        # 140/254) the port is on a wireless SSID segment — the AP management MAC
        # regularly ages out of the FDB while WiFi clients remain visible.
        _WIFI_COMPANION_VLANS_SET = frozenset({30, 40, 50, 130, 140, 254})
        is_trunk_ap_port = (
            is_hub_port_actual  # hub/unmanaged-switch (current or previous snapshot)
            or (current.vlan_id is None and len(current_macs) > 1)
            or len(current_macs) >= _AP_PORT_MAC_COUNT_THRESHOLD
        )
        is_wifi_companion_vlan = current.vlan_id in _WIFI_COMPANION_VLANS_SET

        # Hub / trunk / AP ports: suppress MAC-mismatch alarms unconditionally.
        # The "expected" single MAC on a hub port is just whichever device happened
        # to be first in FDB when the port was registered.  MAC churn on hub ports
        # is completely normal and must never fire an alarm, regardless of whether
        # a MAC-tracking entry exists or has a last_seen timestamp.
        if is_trunk_ap_port:
            self.logger.info(
                f"MAC mismatch suppressed (hub/trunk/AP port): {device.name} port "
                f"{current.port_number} — expected {single_expected}, "
                f"current {len(current_macs)} MAC(s), previous {len(previous_macs_for_hub)} MAC(s). "
                f"Hub port MAC churn is normal. No alarm."
            )
            return None

        mac_tracking_for_grace = session.query(MACAddressTracking).filter(
            MACAddressTracking.mac_address == single_expected
        ).first()

        if mac_tracking_for_grace and mac_tracking_for_grace.last_seen:
            # Port on a WiFi companion VLAN (e.g. VLAN 140 SANTRAL, VLAN 50 DEVICE):
            # the AP management MAC aged out of the FDB; the current MAC(s) are
            # WiFi clients on a wireless SSID VLAN served by the same AP.
            # This is AP oscillation — not a real mismatch.
            if is_wifi_companion_vlan:
                self.logger.info(
                    f"MAC mismatch suppressed (WiFi companion VLAN {current.vlan_id}): "
                    f"{device.name} port {current.port_number} expected {single_expected} "
                    f"absent; port shows WiFi SSID VLAN traffic. AP management MAC aged out. "
                    f"No alarm."
                )
                return None
            secs_absent = (datetime.utcnow() - mac_tracking_for_grace.last_seen).total_seconds()
            # VLAN 1/150/1500 (JACKPOT/DRGT) cihazları FDB'den sık yaşlanır —
            # bu VLAN'lar için kısa bir grace period yeterli (30 dk).
            # Diğer tüm portlar için standart 1 saatlik grace uygulanır.
            grace_period = (
                _LONG_GRACE_PERIOD_SECS
                if current.vlan_id in _LONG_GRACE_VLANS
                else _GRACE_PERIOD_STANDARD_SECS
            )
            if secs_absent < grace_period:
                self.logger.info(
                    f"MAC mismatch grace period: {device.name} port {current.port_number} "
                    f"expected {single_expected} absent for only {secs_absent:.0f}s "
                    f"(< {grace_period}s grace period). "
                    f"Likely FDB aging. No alarm."
                )
                return None

        # Port has MAC(s) but not the expected one - this IS a real mismatch.
        # However, before raising an alarm, check whether any of the currently
        # visible MACs have already been approved by a user (whitelisted).
        # This handles the scenario where:
        #   1. User approves new MAC via UI → added to acknowledged_port_mac
        #   2. But ports.mac was not updated (e.g. JOIN failure in the PHP API)
        #   3. So ports.mac still holds the OLD expected MAC
        #   4. Every poll cycle re-detects the "mismatch" even though user approved it
        # Fix: detect this situation, auto-heal ports.mac, and suppress the alarm.
        whitelisted_actual_mac = None
        for cmac in current_macs:
            if self.db_manager.check_whitelist(session, device.name, current.port_number, cmac):
                whitelisted_actual_mac = cmac
                break

        if whitelisted_actual_mac:
            self.logger.info(
                f"MAC mismatch suppressed: {device.name} port {current.port_number} – "
                f"actual MAC {whitelisted_actual_mac} is whitelisted (user-approved). "
                f"Auto-healing stale ports.mac (was '{single_expected}', "
                f"correcting to '{whitelisted_actual_mac}')."
            )
            # Auto-heal: update ports.mac to the approved MAC so future polls
            # no longer detect a mismatch for this port.
            try:
                session.execute(
                    text("""
                        UPDATE p
                        SET p.mac = :new_mac
                        FROM ports p
                        JOIN switches s ON p.switch_id = s.id
                        JOIN snmp_devices sd ON (s.name = sd.name OR s.ip = sd.ip_address)
                        WHERE sd.id = :device_id
                          AND p.port_no = :port_no
                    """),
                    {
                        "new_mac": whitelisted_actual_mac,
                        "device_id": device.id,
                        "port_no": current.port_number,
                    }
                )
                self.logger.info(
                    f"Auto-healed ports.mac for {device.name} port {current.port_number} "
                    f"→ {whitelisted_actual_mac}"
                )
            except Exception as heal_err:
                self.logger.warning(
                    f"Could not auto-heal ports.mac for {device.name} "
                    f"port {current.port_number}: {heal_err}"
                )
            return None

        actual_mac_list = ','.join(sorted(current_macs))

        # ── VLAN 70 (AP native VLAN) debounce ────────────────────────────────
        # AP trunk ports (PVID = 70) frequently lose the physical AP MAC from the
        # FDB while WiFi client MACs in companion VLANs remain visible.  This is
        # normal FDB ageing on an active AP port and is NOT an unauthorized device
        # swap.  Require _AP_MAC_MISS_THRESHOLD (4) consecutive poll-cycles where
        # the physical MAC is absent before raising a MAC Taşındı alarm — real AP
        # replacements will always be confirmed across multiple polls.
        if current.vlan_id == _AP_NATIVE_VLAN:
            port_key = (device.name, current.port_number)
            miss_count = self._ap_mac_miss_counts.get(port_key, 0) + 1
            self._ap_mac_miss_counts[port_key] = miss_count
            if miss_count < _AP_MAC_MISS_THRESHOLD:
                self.logger.info(
                    f"MAC mismatch debounce (VLAN 70 AP port): {device.name} port "
                    f"{current.port_number} — expected {single_expected} absent, "
                    f"found {actual_mac_list}. "
                    f"Poll {miss_count}/{_AP_MAC_MISS_THRESHOLD} — alarm held."
                )
                return None
            # 4th (or later) consecutive miss: fire the alarm and reset the counter
            # so it can detect a subsequent recovery followed by another real swap.
            self._ap_mac_miss_counts[port_key] = 0
            self.logger.info(
                f"MAC mismatch confirmed (VLAN 70 AP port): {device.name} port "
                f"{current.port_number} — expected {single_expected} absent for "
                f"{_AP_MAC_MISS_THRESHOLD} consecutive polls. Raising MAC Taşındı alarm."
            )
        # ─────────────────────────────────────────────────────────────────────

        change_details = (
            f"{device.name} port {current.port_number} MAC uyuşmazlığı: "
            f"Beklenen '{single_expected}' ancak bulunan '{actual_mac_list}'"
        )

        # Enrich with Device Import info for the newly-detected MAC
        _actual_mac_for_lookup = list(current_macs)[0] if current_macs else actual_mac_list
        _reg_info = self._lookup_mac_in_registry(session, _actual_mac_for_lookup)

        # Build "Mevcut Bağlantı" label: prefer Device Import info over port alias
        if _reg_info:
            _reg_ip, _reg_name = _reg_info
            _reg_parts = [p for p in [_reg_ip, _reg_name] if p]
            _mevcut_label = (' '.join(_reg_parts) + ' olarak kayıtlı') if _reg_parts else current.port_alias
        else:
            _mevcut_label = current.port_alias

        # Append VLAN + Mevcut Bağlantı context
        _ctx_parts = []
        if current.vlan_id:
            _ctx_parts.append(f"VLAN {current.vlan_id}")
        if _mevcut_label:
            _ctx_parts.append(f"Mevcut Bağlantı {_mevcut_label}")
        if _ctx_parts:
            change_details += " " + ", ".join(_ctx_parts) + "."

        self.logger.warning(change_details)

        # Create change history record
        change = PortChangeHistory(
            device_id=device.id,
            port_number=current.port_number,
            change_type=ChangeType.MAC_MOVED,
            change_timestamp=datetime.utcnow(),
            change_details=change_details
        )
        session.add(change)
        session.flush()

        alarm_mac = list(current_macs)[0] if current_macs else None

        alarm, is_new = self.db_manager.get_or_create_alarm(
            session,
            device,
            "mac_moved",
            self._alarm_severity(session, "mac_moved", "HIGH"),
            f"MAC uyuşmazlığı: Port {current.port_number}",
            change_details,
            port_number=current.port_number,
            mac_address=alarm_mac,
            skip_whitelist=True
        )

        if alarm:
            change.alarm_created = True
            change.alarm_id = alarm.id
            alarm.old_value = single_expected
            alarm.new_value = actual_mac_list

            if is_new:
                self.alarm_manager._send_notifications(
                    device,
                    "mac_moved",
                    alarm.severity if alarm.severity else "HIGH",
                    change_details,
                    port_number=current.port_number,
                    port_name=f"Port {current.port_number}",
                    session=session
                )
                alarm.notification_sent = True
                alarm.last_notification_sent = datetime.utcnow()
        else:
            self.logger.error(
                f"MAC uyuşmazlık alarmı oluşturulamadı: "
                f"{device.name} port {current.port_number}"
            )

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
    
    def cleanup_old_snapshots(self, session: Session, days: int = 15) -> int:
        """
        Clean up snapshots older than specified days.

        With the UPSERT approach (one row per device+port) this is largely a
        safety net: it removes rows whose ``snapshot_timestamp`` is older than
        *days* days, which can happen for ports that belong to a device that
        was decommissioned or disabled between cleanup runs.

        Args:
            session: Database session
            days: Number of days to keep (default 15, was 30)

        Returns:
            Number of snapshots deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        deleted = session.query(PortSnapshot).filter(
            PortSnapshot.snapshot_timestamp < cutoff_date
        ).delete()
        
        self.logger.info(f"Cleaned up {deleted} old port snapshots")
        
        return deleted
