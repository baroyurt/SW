"""
Automatic synchronization service.
Syncs SNMP worker data to main switches table automatically.
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import text, func

from models.database import SNMPDevice, PortStatusData
from core.database_manager import DatabaseManager
from core.snmp_client import SNMPClient

# VLAN ID → port type mapping (same mapping as the UI VLAN_TYPE_MAP in index.php)
VLAN_TYPE_MAP: Dict[int, str] = {
    30:   'GUEST',
    40:   'VIP',
    50:   'DEVICE',
    70:   'AP',
    80:   'KAMERA',
    110:  'SES',
    120:  'OTOMASYON',
    130:  'IPTV',
    140:  'SANTRAL',
    150:  'JACKPOT',
    254:  'SERVER',
    1500: 'DRGT',
}

# VLANs where a port with multiple MACs indicates a Hub switch is connected.
# VLAN 50 (DEVICE) and 130 (IPTV): multiple MACs on one port → Hub switch.
# VLAN 80 (KAMERA), 150 (JACKPOT) and 1500 (DRGT): Hub switch expected; list
# all MACs but keep the VLAN type (not HUB), since the device label conveys
# more information than the generic "HUB" label.
_HUB_MULTI_MAC_VLANS = {50, 130}
_MULTI_MAC_PRESERVE_TYPE_VLANS = {80, 150, 1500}

# Only these VLANs trigger automatic MAC registration in mac_device_registry.
# VLAN 150 (JACKPOT) and VLAN 1500 (DRGT) are the only VLANs where hub-port
# MACs should be auto-registered.  Devices on other VLANs (70/AP, 50/DEVICE,
# 80/KAMERA, etc.) must never be overwritten by the autosync process — their
# IP/hostname data comes from Excel imports or manual entry.
_AUTO_REGISTER_VLANS = {150, 1500}


def _collect_all_macs(mac_address: Optional[str], mac_addresses: Optional[str]) -> List[str]:
    """Return a deduplicated ordered list of all MAC addresses for a port."""
    seen_set: set = set()
    ordered: List[str] = []

    def _add(m: str) -> None:
        if m and m not in seen_set:
            seen_set.add(m)
            ordered.append(m)

    if mac_address:
        _add(mac_address)
    if mac_addresses:
        try:
            extras = json.loads(mac_addresses)
            for m in extras:
                _add(m)
        except json.JSONDecodeError:
            pass  # Malformed JSON — skip extra MACs
    return ordered


class AutoSyncService:
    """
    Automatically synchronizes SNMP worker data to main switches database.
    This service runs after each polling cycle to keep the main database updated.
    """

    # Throttle stale-port cleanup to once per day so it doesn't add overhead
    # to every poll cycle (runs every ~60 s).
    _STALE_CLEANUP_INTERVAL_SECONDS = 86400  # 24 hours
    _last_stale_cleanup: Optional[datetime] = None
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize auto sync service.
        
        Args:
            db_manager: Database manager
        """
        self.db_manager = db_manager
        self.logger = logging.getLogger('snmp_worker.autosync')
        
        self.logger.info("Auto Sync Service initialized")
    
    def sync_all_devices(self, session: Session) -> Dict[str, Any]:
        """
        Sync all active SNMP devices to main switches table.
        
        Args:
            session: Database session
            
        Returns:
            Dict with sync results
        """
        synced_count = 0
        error_count = 0
        errors = []
        
        try:
            # Get all active SNMP devices
            devices = session.query(SNMPDevice).filter(
                SNMPDevice.enabled == True
            ).all()
            
            self.logger.info(f"Starting automatic sync for {len(devices)} device(s)")
            
            for device in devices:
                try:
                    self._sync_device(session, device)
                    synced_count += 1
                except Exception as e:
                    error_count += 1
                    error_msg = f"Error syncing {device.name}: {str(e)}"
                    errors.append(error_msg)
                    self.logger.error(error_msg)
            
            # Commit all changes
            session.commit()

            # Virtual core switch creation is now handled via manual DB seed in
            # update_database.php (migrations 64/65).  Auto-creation is disabled
            # to prevent spurious duplicate switches from being generated on every
            # poll cycle.  Only update connection_info_preserved for edge ports
            # that still carry raw LLDP text (not already JSON).
            try:
                self._update_core_port_connections(session)
            except Exception as vcs_e:
                self.logger.warning(f"Core port connection update skipped: {vcs_e}")
            
            if synced_count > 0:
                self.logger.info(
                    f"Auto sync complete: {synced_count} device(s) synchronized, "
                    f"{error_count} error(s)"
                )
            
            # Run stale port cleanup once per day.
            # Clears ports.mac for ports that have been continuously DOWN for
            # stale_port_cleanup_days and whose MAC has moved to a different port.
            now = datetime.utcnow()
            if (AutoSyncService._last_stale_cleanup is None
                    or (now - AutoSyncService._last_stale_cleanup).total_seconds()
                        >= AutoSyncService._STALE_CLEANUP_INTERVAL_SECONDS):
                try:
                    cleanup_days = 7
                    try:
                        from config.config_loader import Config
                        cfg = Config()
                        cleanup_days = int(
                            cfg._config_data.get('maintenance', {}).get(
                                'stale_port_cleanup_days', 7
                            )
                        )
                    except Exception:
                        pass
                    cleaned = self.cleanup_stale_ports(session, cleanup_days)
                    if cleaned > 0:
                        self.logger.info(
                            f"Stale port cleanup: cleared MAC from {cleaned} port(s) "
                            f"(down > {cleanup_days} days with MAC moved away)"
                        )
                    AutoSyncService._last_stale_cleanup = now
                except Exception as cleanup_e:
                    self.logger.warning(f"Stale port cleanup failed: {cleanup_e}")

            return {
                'success': True,
                'synced_count': synced_count,
                'error_count': error_count,
                'errors': errors
            }
            
        except Exception as e:
            session.rollback()
            error_msg = f"Fatal error during auto sync: {str(e)}"
            self.logger.error(error_msg)
            return {
                'success': False,
                'synced_count': synced_count,
                'error_count': error_count + 1,
                'errors': errors + [error_msg]
            }
    
    def _sync_device(self, session: Session, device: SNMPDevice) -> None:
        """
        Sync a single device to main switches table.
        
        Args:
            session: Database session
            device: SNMP device to sync
        """
        # Guard: JSON-named "devices" are phantom artefacts from the old
        # sync_virtual_core_switches() bug.  They must never create a real switch row.
        if device.name and device.name.strip().startswith('{'):
            self.logger.warning(
                f"Skipping JSON-named phantom device: {device.name!r}"
            )
            return

        # Check if switch exists in main table — look up by IP first, then by name.
        # Searching by name as a fallback prevents a duplicate-key IntegrityError
        # when the switch was already added (manually or by a previous autosync run)
        # with a different IP address stored in the switches table.
        result = session.execute(
            text("SELECT id, is_virtual FROM switches WHERE ip = :ip"),
            {"ip": device.ip_address}
        ).fetchone()

        if result is None:
            result = session.execute(
                text("SELECT id, is_virtual FROM switches WHERE name = :name"),
                {"name": device.name}
            ).fetchone()

        # If still no match, check whether the device name is a prefix of a seeded
        # virtual/core switch (e.g. physical "CHAMADA-9606-CORESW" vs. seeded
        # "CHAMADA-9606-CORESW-1" / "CHAMADA-9606-CORESW-2").  When such a prefix
        # match exists the SNMP device is the physical chassis behind the virtual
        # switch; skip it entirely to avoid creating a duplicate phantom switch and
        # to preserve the carefully seeded virtual switch data.
        if result is None:
            prefix_match = session.execute(
                text("""
                    SELECT TOP 1 id, is_virtual FROM switches
                    WHERE name LIKE :prefix
                      AND (is_core = 1 OR is_virtual = 1)
                """),
                {"prefix": device.name.strip() + '%'}
            ).fetchone()
            if prefix_match:
                self.logger.info(
                    f"SNMP device '{device.name}' is the physical chassis of virtual switch "
                    f"(id={prefix_match[0]}) — skipping to preserve virtual switch data"
                )
                return

        if result:
            # Never overwrite seeded virtual/core switches (is_virtual=1).
            # These are managed manually; letting autosync rename them would
            # corrupt their carefully seeded names.
            if result[1]:  # is_virtual == 1
                self.logger.debug(
                    f"Skipping autosync update for virtual switch (id={result[0]}): {device.name}"
                )
                # Do NOT sync ports for virtual switches — their ports are seeded
                # manually and must not be overwritten by physical SNMP data.
                return

            # Update existing switch
            switch_id = result[0]
            
            status = 'online' if device.status.value.upper() == 'ONLINE' else 'offline'
            
            session.execute(
                text("""
                    UPDATE switches 
                    SET name = :name, 
                        brand = :brand, 
                        model = :model, 
                        ports = :ports, 
                        ip = :ip,
                        status = :status
                    WHERE id = :id
                """),
                {
                    "name": device.name,
                    "brand": device.vendor,
                    "model": device.model,
                    "ports": device.total_ports,
                    "ip": device.ip_address,
                    "status": status,
                    "id": switch_id
                }
            )
            
            self.logger.debug(f"Updated switch: {device.name} (ID: {switch_id})")
            
        else:
            # Insert new switch
            result = session.execute(
                text("""
                    INSERT INTO switches (name, brand, model, ports, ip, status)
                    VALUES (:name, :brand, :model, :ports, :ip, 'online')
                """),
                {
                    "name": device.name,
                    "brand": device.vendor,
                    "model": device.model,
                    "ports": device.total_ports,
                    "ip": device.ip_address
                }
            )
            
            switch_id = result.lastrowid
            
            self.logger.info(f"Created new switch: {device.name} (ID: {switch_id})")
        
        # Sync port data
        self._sync_ports(session, device, switch_id)
    
    def _sync_ports(self, session: Session, device: SNMPDevice, switch_id: int) -> None:
        """
        Sync port data for a device.
        
        Args:
            session: Database session
            device: SNMP device
            switch_id: Main switches table ID
        """
        # Get latest port data – one row per port_number (latest by id).
        # Cannot use "poll_timestamp == MAX(poll_timestamp)" because each port
        # is saved with a separate datetime.utcnow() call (microseconds apart),
        # so only the very last saved port would match the exact max timestamp.
        # Instead: sub-select MAX(id) per port_number, then join back.
        latest_id_subq = (
            session.query(
                PortStatusData.port_number,
                func.max(PortStatusData.id).label('max_id')
            )
            .filter(PortStatusData.device_id == device.id)
            .group_by(PortStatusData.port_number)
            .subquery()
        )
        latest_ports = (
            session.query(PortStatusData)
            .join(
                latest_id_subq,
                (PortStatusData.device_id == device.id) &
                (PortStatusData.port_number == latest_id_subq.c.port_number) &
                (PortStatusData.id == latest_id_subq.c.max_id)
            )
            .all()
        )
        
        # Determine fiber port range: last 4 ports (e.g., 25-28 for a 28-port switch)
        total_ports = device.total_ports or 0
        # Use total_ports - 3 for real switches (>= 8 ports); default to 25 for unknown/unset
        fiber_port_min = (total_ports - 3) if total_ports >= 8 else 25

        # Collect LLDP neighbor data — applied to ALL ports, not just fiber range.
        # fiber_port_min is still used as a soft hint but CORESW neighbors found on
        # any port will be written regardless of port number.
        lldp_neighbors: Dict[int, Dict[str, str]] = {}
        try:
            snmp_client = self._create_snmp_client_for_device(device)
            if snmp_client:
                lldp_neighbors = snmp_client.get_lldp_neighbors()

                # ── Resolve sys_name from mgmt_ip when lldpRemSysName is absent ───
                # Some device pairs (e.g. CBS350 ↔ Catalyst 9606) only advertise
                # lldpRemPortDesc and lldpRemManAddr but not lldpRemSysName.
                # Pre-load a mapping: management_IP → switch_name for core switches.
                if lldp_neighbors:
                    try:
                        ip_map_rows = session.execute(text("""
                            SELECT s.name AS sw_name, sd.ip_address
                            FROM   switches s
                            JOIN   snmp_devices sd
                                   ON (sd.name = s.name OR sd.ip_address = s.ip)
                            WHERE  s.is_core = 1
                              AND  LEFT(s.name, 1) != '{'
                              AND  sd.ip_address IS NOT NULL
                              AND  sd.ip_address != ''
                        """)).fetchall()
                        core_ip_to_name: dict = {r.ip_address: r.sw_name for r in ip_map_rows}
                    except Exception:
                        core_ip_to_name = {}

                    for _port_num, neighbor in lldp_neighbors.items():
                        if not neighbor.get('system_name') and neighbor.get('mgmt_ip'):
                            resolved = core_ip_to_name.get(neighbor['mgmt_ip'], '')
                            if resolved:
                                neighbor['system_name'] = resolved

                if lldp_neighbors:
                    coresw_neighbors = {k: v for k, v in lldp_neighbors.items()
                                        if 'CORESW' in v.get('system_name', '').upper()
                                        or 'CORESW' in v.get('port_desc', '').upper()}
                    self.logger.info(
                        f"LLDP: {device.name} — {len(lldp_neighbors)} neighbor(s) total, "
                        f"{len(coresw_neighbors)} CORESW neighbor(s): "
                        f"{list(coresw_neighbors.keys())}"
                    )
                else:
                    self.logger.info(f"LLDP: {device.name} — no LLDP neighbors returned")
        except Exception as e:
            self.logger.warning(f"Could not collect LLDP data for {device.name}: {type(e).__name__}: {e}")

        ports_synced = 0
        
        # Load uplink ports for this device (skip MAC collection on these ports)
        try:
            uplink_rows = session.execute(
                text("SELECT port_number FROM snmp_uplink_ports WHERE device_id = :did"),
                {"did": device.id}
            ).fetchall()
            uplink_port_numbers = {row[0] for row in uplink_rows}
        except Exception as _ue:
            self.logger.debug(f"Could not load uplink ports for {device.name} (table may not exist yet): {_ue}")
            uplink_port_numbers = set()

        # Load core-switch uplink ports for this device.
        # Used to prevent raw LLDP text (without "CORESW") from overwriting a
        # registered core port's connection_info_preserved when LLDP temporarily
        # fails to advertise the core switch system name.
        try:
            core_up_rows = session.execute(
                text("SELECT port_number FROM snmp_core_ports WHERE device_id = :did"),
                {"did": device.id}
            ).fetchall()
            core_port_numbers = {row[0] for row in core_up_rows}
        except Exception as _ce:
            self.logger.debug(f"Could not load core ports for {device.name}: {_ce}")
            core_port_numbers = set()

        for port in latest_ports:
            try:
                # Check if port exists – also read existing device/ip to avoid wiping user data
                result = session.execute(
                    text("SELECT id, type, device, ip, connection_info_preserved FROM ports WHERE switch_id = :switch_id AND port_no = :port_no"),
                    {"switch_id": switch_id, "port_no": port.port_number}
                ).fetchone()

                is_up = port.oper_status.value == 'up' and port.admin_status.value == 'up'
                oper_status_str = 'up' if is_up else 'down'

                # For uplink ports: only track up/down status, skip all MAC collection.
                is_uplink = port.port_number in uplink_port_numbers
                if is_uplink:
                    # Update oper_status only; leave MAC/IP/device/type unchanged.
                    # Only write when the polled status is definitively 'up' or 'down'.
                    # Skip the update when psd_oper_status is 'unknown' (e.g. CBS350
                    # SFP+ port with no module returns ifOperStatus=notPresent which
                    # maps to PortStatus.UNKNOWN).  Writing 'down' in that case would
                    # wrongly show an SFP port with no module inserted as "port down"
                    # in getData.php's fallback path (psd_oper_status='unknown' →
                    # fallback to ports.oper_status).
                    if result and port.oper_status.value in ('up', 'down'):
                        session.execute(
                            text("UPDATE ports SET oper_status = :oper_status, updated_at = GETDATE() WHERE id = :id"),
                            {"oper_status": oper_status_str, "id": result[0]}
                        )
                    ports_synced += 1
                    continue

                # Collect ALL MACs for this port (first MAC + any additional ones
                # stored as JSON in mac_addresses).  Multiple MACs on a single
                # non-AP port indicate a Hub switch is connected.
                all_macs = _collect_all_macs(port.mac_address, port.mac_addresses)
                # Primary MAC for alarm / tracking purposes
                mac_address = all_macs[0] if all_macs else ''
                # Write comma-separated MACs to the ports table so that getData.php
                # can detect Hub switches via its isHubFromData() function.
                mac_str = ','.join(all_macs) if all_macs else ''

                # Determine the SNMP-provided port label.
                # CBS350 reports ifAlias (port_alias) only when the admin sets a
                # description on the port; ifName (port_name) is always "GEX".
                # Prefer alias; fall back to name only for new (INSERT) rows.
                snmp_alias = (port.port_alias or '').strip()
                snmp_name  = (port.port_name  or '').strip()

                meaningful_types = {
                    'DEVICE', 'SERVER', 'AP', 'KAMERA', 'TV',
                    'OTOMASYON', 'SANTRAL', 'FIBER', 'ETHERNET', 'HUB',
                    'GUEST', 'VIP', 'SES', 'JACKPOT', 'DRGT',
                }

                # Effective VLAN: use what Python SNMP directly detected this cycle.
                # With lookupMib=False, Python reliably detects real VLANs (50, 120, 130, etc.).
                # If vlan_id=1 or None (SNMP walk failed), effective_vlan=None → preserve type.
                effective_vlan = port.vlan_id if (port.vlan_id and port.vlan_id > 1) else None

                # Determine port type:
                # 1. If port is DOWN → keep existing meaningful type, oper_status='down'
                # 2. If port is UP + multiple MACs on a Hub-detectable VLAN → 'HUB'
                # 3. If port is UP + VLAN known → mapped device type (auto-correct user type)
                # 4. If port is UP + VLAN unknown (not in map) → "VLAN X" (red in UI)
                # 5. If port is UP + no VLAN detected at all → preserve existing or 'DEVICE'
                #
                # Hub switch detection: multiple MACs on a single port means a Hub or
                # unmanaged switch is connected.  Apply this rule for VLANs 50 (DEVICE)
                # and 130 (TV).  VLANs 150 (JACKPOT) and 1500 (DRGT) also commonly have
                # multiple MACs; keep their specific type so the UI shows JACKPOT/DRGT
                # rather than the generic HUB label (all MACs are still written to the
                # mac field so getData.php can count them).
                is_multi_mac = len(all_macs) > 1
                if not is_up:
                    existing_type = result[1] if result else None
                    # Priority: VLAN data (ground truth) > any existing meaningful type > EMPTY.
                    # VLAN always wins so stale type labels (e.g. 'ETHERNET') are
                    # auto-corrected once VLAN info is available from the bitmask walk.
                    if effective_vlan and effective_vlan in VLAN_TYPE_MAP:
                        port_type = VLAN_TYPE_MAP[effective_vlan]
                    elif effective_vlan:
                        port_type = f'VLAN {effective_vlan}'
                    elif existing_type and (existing_type in meaningful_types or
                                            existing_type.startswith('VLAN ')):
                        port_type = existing_type  # preserve when no VLAN data
                    else:
                        port_type = 'EMPTY'
                elif is_multi_mac and effective_vlan in _HUB_MULTI_MAC_VLANS:
                    # Multiple MACs on a DEVICE/TV VLAN → Hub switch
                    port_type = 'HUB'
                    self.logger.info(
                        f"Port {port.port_number} VLAN {effective_vlan}: "
                        f"{len(all_macs)} MACs → HUB"
                    )
                elif effective_vlan and effective_vlan in VLAN_TYPE_MAP:
                    port_type = VLAN_TYPE_MAP[effective_vlan]
                    self.logger.info(
                        f"Port {port.port_number} VLAN {effective_vlan} → {port_type}"
                    )
                elif effective_vlan:
                    # Non-default VLAN not in map → show as "VLAN X" (red)
                    port_type = f'VLAN {effective_vlan}'
                    self.logger.info(
                        f"Port {port.port_number} unknown VLAN {effective_vlan} → {port_type}"
                    )
                else:
                    # No VLAN info at all — preserve existing meaningful type or use DEVICE
                    existing_type = result[1] if result else None
                    if existing_type and existing_type in meaningful_types:
                        port_type = existing_type
                    else:
                        port_type = 'DEVICE'  # safe default

                # Core uplink fiber ports must always show as FIBER regardless of what
                # VLAN detection returned (e.g. native VLAN 50 → DEVICE is incorrect
                # for a physical fiber uplink to a core switch).
                if is_up and port.port_number in core_port_numbers:
                    port_type = 'FIBER'

                # Build LLDP connection info.
                # Applied to ALL ports that have an LLDP neighbor entry.
                # The fiber_port_min hint is used only as a secondary preference:
                # uplink/fiber ports (>= fiber_port_min) are checked first, but if
                # a CORESW neighbor is seen on any port, it is always written.
                lldp_info: Optional[str] = None
                if port.port_number in lldp_neighbors:
                    neighbor = lldp_neighbors[port.port_number]
                    sys_name   = neighbor.get('system_name', '').strip()
                    port_desc  = neighbor.get('port_desc',   '').strip()
                    chassis_id = neighbor.get('chassis_id',  '').strip()
                    parts = [p for p in [sys_name, port_desc, chassis_id] if p]
                    if parts:
                        lldp_info = ' | '.join(parts)
                
                if result:
                    # Update existing port
                    port_id = result[0]
                    existing_type = (result[1] or '').strip()
                    
                    if is_up:
                        # For UP ports: always update type/oper_status/mac.
                        # Preserve user-set device name and IP:
                        #   - Keep the existing device name exactly as stored; never overwrite
                        #     it with SNMP alias or mac_device_registry on UPDATE.
                        #   - If the user (or a bulk reset) cleared device to '', it stays ''
                        #     until the user manually re-enters a name.  This ensures that
                        #     "reset all ports" actually clears device labels permanently.
                        #   - SNMP alias is stored in port_status_data.port_alias and shown in
                        #     the UI as a card subtitle — it must not be written to ports.device.
                        #   - Never clear the IP address that the user manually entered.
                        existing_device = (result[2] or '').strip() if result else ''
                        # On UPDATE, always preserve what is stored (including empty string).
                        new_device = existing_device
                        if mac_str:
                            # Worker detected MAC(s) (from FDB table) — write them.
                            # Multiple MACs are written comma-separated so getData.php
                            # can detect Hub switches via isHubFromData().
                            session.execute(
                                text("""
                                    UPDATE ports 
                                    SET type = :type,
                                        oper_status = :oper_status,
                                        device = :device,
                                        mac = :mac
                                    WHERE id = :id
                                """),
                                {
                                    "type": port_type,
                                    "oper_status": oper_status_str,
                                    "device": new_device,
                                    "mac": mac_str,
                                    "id": port_id
                                }
                            )
                        else:
                            # No MAC detected this cycle — preserve existing mac to avoid
                            # clearing user-entered or previously FDB-detected values.
                            session.execute(
                                text("""
                                    UPDATE ports 
                                    SET type = :type,
                                        oper_status = :oper_status,
                                        device = :device
                                    WHERE id = :id
                                """),
                                {
                                    "type": port_type,
                                    "oper_status": oper_status_str,
                                    "device": new_device,
                                    "id": port_id
                                }
                            )

                        # Fire VLAN change alarm when SNMP-derived type differs from stored type.
                        # This catches both: switch admin changed VLAN config, and UI type mismatch.
                        # Suppress when the transition involves AP (VLAN 70) ↔ WiFi SSID VLANs —
                        # these are virtual wireless VLANs carried by an AP trunk port, not real
                        # physical reconfiguration.
                        # WiFi companion types: GUEST (30), VIP (40), DEVICE (50), IPTV (130),
                        # SANTRAL (140), SERVER (254).
                        _WIFI_AP_COMPANION_TYPES = {
                            'GUEST', 'VIP', 'DEVICE', 'IPTV', 'TV', 'SANTRAL', 'SERVER'
                        }
                        _is_wifi_type_transition = (
                            (existing_type == 'AP' and port_type in _WIFI_AP_COMPANION_TYPES) or
                            (port_type == 'AP' and existing_type in _WIFI_AP_COMPANION_TYPES) or
                            (existing_type in _WIFI_AP_COMPANION_TYPES and port_type in _WIFI_AP_COMPANION_TYPES)
                        )
                        # Suppress any transition that involves HUB on either side.
                        # HUB is a dynamic classification based on the number of MACs
                        # seen in the FDB table during a single polling cycle.  When an
                        # unmanaged switch is connected on a DEVICE/TV VLAN, the FDB
                        # scan sometimes sees multiple MACs (→ HUB) and sometimes only
                        # one (→ DEVICE or → TV) depending on timing.  This oscillation
                        # is NOT a real VLAN reconfiguration, so suppress any alarm where
                        # either the old or new type is HUB.
                        _involves_hub_type = (
                            existing_type == 'HUB' or port_type == 'HUB'
                        )
                        if (effective_vlan and effective_vlan > 1
                                and existing_type and existing_type != port_type
                                and existing_type in meaningful_types
                                and port_type in meaningful_types
                                and not _is_wifi_type_transition
                                and not _involves_hub_type):
                            try:
                                change_details = (
                                    f"{device.name} port {port.port_number} VLAN tipi değişti: "
                                    f"{existing_type} → {port_type} (VLAN {effective_vlan})"
                                )
                                alarm, _ = self.db_manager.get_or_create_alarm(
                                    session,
                                    device,
                                    "vlan_changed",
                                    "MEDIUM",
                                    f"VLAN tipi değişti: Port {port.port_number}",
                                    change_details,
                                    port_number=port.port_number,
                                    old_vlan_id=effective_vlan,
                                    new_vlan_id=effective_vlan,
                                )
                                if alarm:
                                    alarm.old_value = existing_type
                                    # Include old type in parentheses so the UI shows
                                    # e.g. "HUB(DEVICE)" instead of just "HUB", giving
                                    # context about which VLAN the port was on before.
                                    alarm.new_value = f"{port_type}({existing_type})"
                                self.logger.info(change_details)
                            except Exception as alarm_e:
                                self.logger.debug(
                                    f"Could not create type-mismatch alarm for port "
                                    f"{port.port_number}: {alarm_e}"
                                )
                    else:
                        # Port is DOWN: update type+oper_status, preserve device/ip/mac/connection_info_preserved
                        session.execute(
                            text("UPDATE ports SET type = :type, oper_status = :oper_status WHERE id = :id"),
                            {"type": port_type, "oper_status": oper_status_str, "id": port_id}
                        )

                    # Write LLDP info to connection_info_preserved for fiber ports.
                    # When LLDP reports a CORESW neighbor, always write the raw text so
                    # that sync_core_ports.php can rebuild the virtual_core JSON on the
                    # next pass (even if a stale JSON was already stored there).
                    # For non-CORESW LLDP text: skip if existing JSON is already present
                    # or if this is a known core uplink (preserve its virtual_core JSON).
                    if lldp_info is not None:
                        # result columns: (id[0], type[1], device[2], ip[3], connection_info_preserved[4])
                        existing_ci = (result[4] or '').strip() if result else ''
                        lldp_has_coresw = 'CORESW' in lldp_info.upper()
                        is_core_uplink  = port.port_number in core_port_numbers
                        # Allow write when:
                        #   - LLDP mentions CORESW → always overwrite (keep sync fresh)
                        #   - OR no existing JSON and not a non-CORESW core uplink
                        should_write_lldp = (
                            lldp_has_coresw
                            or (not existing_ci.startswith('{') and (not is_core_uplink or lldp_has_coresw))
                        )
                        if should_write_lldp:
                            session.execute(
                                text("""
                                    UPDATE ports SET connection_info_preserved = :lldp_info
                                    WHERE id = :id
                                """),
                                {"lldp_info": lldp_info, "id": port_id}
                            )
                else:
                    # Insert new port
                    session.execute(
                        text("""
                            INSERT INTO ports (switch_id, port_no, type, oper_status, device, mac, connection_info_preserved)
                            VALUES (:switch_id, :port_no, :type, :oper_status, :device, :mac, :conn_info)
                        """),
                        {
                            "switch_id": switch_id,
                            "port_no": port.port_number,
                            "type": port_type,
                            "oper_status": oper_status_str,
                            "device": snmp_alias or snmp_name,
                            "mac": mac_str,
                            "conn_info": lldp_info or ''
                        }
                    )
                
                ports_synced += 1

                # Auto-register MACs for JACKPOT (150) / DRGT (1500) Hub ports.
                # These are unmanaged-switch ports where every MAC is a physical
                # device.  Register each MAC in mac_device_registry with the VLAN
                # name as both IP and Hostname (no IP scan performed).
                # Only VLANs in _AUTO_REGISTER_VLANS are registered; other VLANs
                # (70/AP, 50/DEVICE, 80/KAMERA, etc.) must not be touched so that
                # user-entered or Excel-imported IP/hostname data is preserved.
                if (is_up and effective_vlan in _AUTO_REGISTER_VLANS
                        and len(all_macs) > 0):
                    vlan_label = VLAN_TYPE_MAP.get(effective_vlan, str(effective_vlan))
                    self._register_hub_macs(session, all_macs, vlan_label)
                
            except Exception as e:
                self.logger.warning(f"Error syncing port {port.port_number} on {device.name}: {e}")
        
        if ports_synced > 0:
            self.logger.debug(f"Synced {ports_synced} port(s) for {device.name}")

    def _register_hub_macs(self, session, macs: List[str], vlan_label: str) -> None:
        """Auto-register JACKPOT/DRGT Hub MACs in mac_device_registry.

        For unmanaged-switch ports on VLAN 150 (JACKPOT) and VLAN 1500 (DRGT),
        each MAC address is a physical device.  Register / update each one in
        ``mac_device_registry`` with:
          - mac_address  = the actual MAC
          - ip_address   = VLAN name (e.g. "JACKPOT")
          - device_name  = VLAN name
          - source       = 'snmp_hub_auto'

        No IP-address lookup or DNS resolution is performed — the VLAN label
        serves as the IP placeholder so the UI shows the device class.

        Entries that were previously set via Excel import ('excel'), manual
        entry ('manual'), or any other non-auto source are NOT overwritten —
        only entries with source='snmp_hub_auto' (previously auto-registered)
        are updated in-place.
        """
        import re
        for mac in macs:
            try:
                # Normalize to uppercase colon-separated form (e.g. AA:BB:CC:DD:EE:FF)
                hex_only = re.sub(r'[^0-9A-Fa-f]', '', mac).upper()
                if len(hex_only) != 12:
                    self.logger.debug(f"Hub MAC auto-register skipped (invalid): {mac}")
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
                    f"Hub MAC auto-registered: {mac_norm} → {vlan_label}"
                )
            except Exception as e:
                self.logger.warning(
                    f"Hub MAC auto-register failed for {mac}: {e}"
                )

    def cleanup_stale_ports(self, session: Session, cleanup_days: int = 7) -> int:
        """
        Clear MAC address from ports that have been DOWN for cleanup_days and whose
        MAC has moved to a different port (or is no longer seen anywhere in FDB).

        Conditions for clearing a port's MAC (all must hold):
          1. ports.oper_status = 'down'  (port has been inactive)
          2. ports.mac is not empty and contains a single MAC (not a hub comma-list)
          3. mac_address_tracking.last_seen < now - cleanup_days
             (the MAC has not appeared in any FDB for at least cleanup_days)
          4. The MAC's current tracked location differs from this port on EITHER
             the device OR the port number (OR condition — if the MAC moved to a
             different switch OR to a different port on the same switch, clear it)

        Only single-MAC (non-hub) ports are touched.  Hub ports are managed
        exclusively by the per-cycle autosync logic.  A port is considered a hub
        port when ports.mac contains a comma (e.g. 'AA:BB:CC:DD:EE:FF,11:22:33:44:55:66').

        Returns the number of ports whose MAC was cleared.
        """
        cutoff = datetime.utcnow() - timedelta(days=cleanup_days)
        try:
            result = session.execute(
                text("""
                    UPDATE p
                    SET    p.mac    = '',
                           p.is_hub = 0
                    FROM   ports p
                    INNER JOIN switches sw ON sw.id = p.switch_id
                    -- LEFT JOIN: a switch may not have an snmp_devices entry yet;
                    -- sd.id IS NULL is a valid case that means the MAC could not
                    -- have been seen by the SNMP worker → safe to clear.
                    LEFT  JOIN snmp_devices sd ON sd.name = sw.name
                    INNER JOIN mac_address_tracking mat
                           ON  mat.mac_address = p.mac
                    WHERE  p.oper_status  = 'down'
                      AND  p.mac         IS NOT NULL
                      AND  p.mac         != ''
                      -- Skip hub ports: autosync manages multi-MAC ports via
                      -- comma-separated values; single-MAC ports have no comma.
                      AND  p.mac         NOT LIKE '%,%'
                      AND  mat.last_seen  < :cutoff
                      AND  (
                               -- MAC no longer tracked anywhere
                               mat.current_device_id  IS NULL
                               -- Switch has no SNMP device record
                            OR sd.id                  IS NULL
                               -- MAC moved to a different switch
                            OR mat.current_device_id != sd.id
                               -- MAC moved to a different port on the same switch
                            OR mat.current_port_number != p.port_no
                           )
                """),
                {"cutoff": cutoff}
            )
            return result.rowcount
        except Exception as e:
            self.logger.warning(f"cleanup_stale_ports query failed: {e}")
            return 0

    def _create_snmp_client_for_device(self, device: SNMPDevice) -> Optional[SNMPClient]:
        """
        Create an SNMP client for a device using its stored credentials.
        
        Args:
            device: SNMP device model
            
        Returns:
            SNMPClient or None if not possible
        """
        try:
            kwargs: Dict[str, Any] = {
                'host': device.ip_address,
                'version': device.snmp_version or '2c',
                'timeout': 3,
                'retries': 1
            }
            
            if device.snmp_version == '3':
                v3_config = {
                    'username': device.snmp_v3_username or 'snmpuser',
                    'auth_protocol': device.snmp_v3_auth_protocol or 'SHA',
                    'auth_password': device.snmp_v3_auth_password or '',
                    'priv_protocol': device.snmp_v3_priv_protocol or 'AES',
                    'priv_password': device.snmp_v3_priv_password or '',
                    'engine_id': device.snmp_engine_id or ''
                }
                kwargs.update({
                    'username': v3_config['username'],
                    'auth_protocol': v3_config['auth_protocol'],
                    'auth_password': v3_config['auth_password'],
                    'priv_protocol': v3_config['priv_protocol'],
                    'priv_password': v3_config['priv_password'],
                    'engine_id': v3_config['engine_id']
                })
            else:
                kwargs['community'] = device.snmp_community or 'public'
            
            return SNMPClient(**kwargs)
        except Exception as e:
            self.logger.debug(f"Could not create SNMP client for {device.name}: {e}")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Virtual Core Switch auto-creation from LLDP data
    # ─────────────────────────────────────────────────────────────────────────

    def _update_core_port_connections(self, session: Session) -> None:
        """
        Lightweight replacement for the old sync_virtual_core_switches().

        Rules (to prevent the runaway-duplicate-switch bug):
        ─────────────────────────────────────────────────────
        • NEVER create new switch rows.  The two canonical core switches
          (CHAMADA-9606-CORESW-1, CHAMADA-9606-CORESW-2) are seeded once
          via update_database.php migrations 64/65.
        • NEVER create new rack rows.
        • Skip any port whose connection_info_preserved is already a JSON
          object (starts with '{') — it has been processed before.
        • For ports that still carry raw LLDP text containing "CORESW",
          look up the matching seeded core switch and update
          connection_info_preserved to the canonical JSON payload so the
          UI tooltip shows correct data.
        • ALSO update the core switch's own port with a reverse-connection
          JSON so the core switch detail page shows which edge switch is
          connected to each fiber port.
        """


        def _apply_reverse_to_core_port(
            session, core_sw_id, core_port_no, edge_sw_id, edge_sw_name, edge_port_no
        ):
            """Write/update the reverse-connection JSON on a core switch port."""
            if not core_port_no:
                return
            reverse_ci = json.dumps({
                "type": "virtual_core_reverse",
                "edge_switch_id": edge_sw_id,
                "edge_switch_name": edge_sw_name,
                "edge_port_no": edge_port_no,
            }, ensure_ascii=False)
            session.execute(text("""
                UPDATE ports SET connection_info_preserved = :ci
                WHERE switch_id = :sw_id AND port_no = :port_no
            """), {"ci": reverse_ci, "sw_id": core_sw_id, "port_no": core_port_no})

        try:
            # Fetch all edge ports with raw LLDP text referencing a core switch.
            # Also fetch the parent switch name so we can store it in the reverse JSON.
            rows = session.execute(text("""
                SELECT p.id           AS port_id,
                       p.switch_id,
                       p.port_no,
                       p.connection_info_preserved AS raw,
                       s.name         AS switch_name
                FROM   ports p
                JOIN   switches s ON s.id = p.switch_id
                WHERE  p.connection_info_preserved IS NOT NULL
                  AND  p.connection_info_preserved != ''
                  AND  p.connection_info_preserved NOT LIKE '{%'
                  AND  p.connection_info_preserved LIKE '%CORESW%'
            """)).fetchall()

            # Fetch the two seeded core switches — exclude any JSON-named phantom
            # switches that might have is_core=1 set erroneously.
            core_rows = session.execute(text(
                "SELECT id, name FROM switches WHERE is_core = 1 AND LEFT(name,1) != '{'"
            )).fetchall()
            # Build a mapping: normalised base-name → list of {id, name}
            # e.g. "CHAMADA-9606-CORESW" → both -1 and -2 entries
            core_by_base: dict = {}
            for cr in core_rows:
                # "CHAMADA-9606-CORESW-1" → base "CHAMADA-9606-CORESW"
                base = re.sub(r'-\d+$', '', cr.name)
                core_by_base.setdefault(base, []).append({'id': cr.id, 'name': cr.name})

            updated = 0
            for row in rows:
                raw = (row.raw or '').strip()
                parts = [p.strip() for p in raw.split('|')]
                if not parts:
                    continue

                # Derive the slot from the remote port description
                # e.g. "TwentyFiveGigE1/1/0/26" → slot 1 → CHAMADA-9606-CORESW-1
                remote_port_label = parts[1] if len(parts) > 1 else ''
                slot_match = re.search(r'(?:GigE|gige)(\d+)/', remote_port_label, re.IGNORECASE)
                slot = int(slot_match.group(1)) if slot_match else None

                # Parse core base name from first segment
                full_name = parts[0]
                # "CHAMADA-9606-CORESW.chamada.prestige" → "CHAMADA-9606-CORESW"
                core_base = full_name.split('.')[0].strip() if '.' in full_name else full_name.strip()
                if not core_base:
                    continue

                # Find matching seeded switch
                candidates = core_by_base.get(core_base, [])
                if not candidates:
                    # Try a prefix match
                    for base_key, cands in core_by_base.items():
                        if core_base.startswith(base_key) or base_key.startswith(core_base):
                            candidates = cands
                            break

                if not candidates:
                    self.logger.debug(
                        f"No seeded core switch found for '{core_base}' — skipping port {row.port_id}"
                    )
                    continue

                # Pick the candidate matching the slot, or default to first
                core_sw = None
                if slot is not None:
                    for c in candidates:
                        if c['name'].endswith(f'-{slot}'):
                            core_sw = c
                            break
                if core_sw is None:
                    core_sw = candidates[0]

                # Extract port number from label: TwentyFiveGigE{sw}/{module}/0/{port}
                # Formula: port_no = (module - 1) * 48 + port_within_module
                # Each module has 48 ports: module 1 → ports 1–48, module 2 → ports 49–96
                # e.g. TwentyFiveGigE1/1/0/26 → (1-1)*48+26 = 26
                #      TwentyFiveGigE1/2/0/26 → (2-1)*48+26 = 74
                # Also handle abbreviated forms: Tw1/1/0/26, TwG1/1/0/26, Te1/1/0/26 (same calc)
                # 3-segment abbreviated ports (Te1/1/1, Gi1/1/1): use last segment as port number
                port_label_match = re.search(r'/(\d+)/0/(\d+)$', remote_port_label)
                if port_label_match:
                    _mod = int(port_label_match.group(1))
                    _port_within = int(port_label_match.group(2))
                    core_port_no = (_mod - 1) * 48 + _port_within
                else:
                    # 3-segment format (Te1/1/1, Gi1/0/1, etc.) — use last segment as port
                    three_seg_match = re.search(r'\d+/\d+/(\d+)$', remote_port_label)
                    if three_seg_match:
                        core_port_no = int(three_seg_match.group(1))
                    else:
                        core_port_no = 0

                new_ci = json.dumps({
                    "type": "virtual_core",
                    "core_switch_id": core_sw['id'],
                    "core_switch_name": core_sw['name'],
                    "core_port_no": core_port_no,
                    "core_port_label": remote_port_label,
                    "raw_lldp": raw
                }, ensure_ascii=False)

                session.execute(text(
                    "UPDATE ports SET connection_info_preserved = :ci WHERE id = :id"
                ), {"ci": new_ci, "id": row.port_id})

                # Also write reverse connection to the core switch port so the
                # core switch detail page shows which edge switch is connected.
                _apply_reverse_to_core_port(
                    session,
                    core_sw['id'], core_port_no,
                    row.switch_id, row.switch_name, row.port_no
                )

                updated += 1

            if updated:
                session.commit()
                self.logger.info(
                    f"Core port connections updated: {updated} edge port(s) migrated to JSON format"
                )

            # ── Second pass ─────────────────────────────────────────────────
            # Edge ports that were already converted to JSON in a previous cycle
            # are skipped by the query above.  But their corresponding core switch
            # ports may still lack the reverse-connection JSON (e.g. after the DB
            # was cleaned up).  Scan all virtual_core JSON edge ports and fill in
            # any core switch port that is still missing reverse info.
            # ALSO propagate edge port oper_status to the core switch port so the
            # core switch UI shows each port as up/down based on the edge fiber port.
            # ALSO auto-register edge switch fiber ports in snmp_core_ports so that
            # the alarm manager fires core_link_down alarms when they go down.
            json_rows = session.execute(text("""
                SELECT p.switch_id,
                       p.port_no,
                       p.oper_status AS edge_oper_status,
                       p.connection_info_preserved AS ci,
                       s.name AS switch_name,
                       sd.id AS sd_id
                FROM   ports p
                JOIN   switches s ON s.id = p.switch_id
                LEFT JOIN snmp_devices sd ON (sd.name = s.name OR sd.ip_address = s.ip)
                WHERE  p.connection_info_preserved LIKE '{\"type\": \"virtual_core\"%'
                    OR p.connection_info_preserved LIKE '{\"type\":\"virtual_core\"%'
            """)).fetchall()

            reverse_updated = 0
            for jrow in json_rows:
                try:
                    ci_data = json.loads(jrow.ci)
                    if ci_data.get('type') != 'virtual_core':
                        continue
                    core_sw_id    = ci_data.get('core_switch_id')
                    core_port_no  = ci_data.get('core_port_no', 0)
                    core_port_label = ci_data.get('core_port_label', '')
                    core_sw_name  = ci_data.get('core_switch_name', '')
                    if not core_sw_id or not core_port_no:
                        continue

                    # Patch raw_lldp if it is empty — synthesise from core switch name
                    # and port label so the tooltip and snmp_port_detail.php can show
                    # the correct CORESW connection even when LLDP data was lost.
                    if not ci_data.get('raw_lldp', '').strip():
                        ci_data['raw_lldp'] = (
                            f"{core_sw_name} | {core_port_label}"
                            if core_port_label else core_sw_name
                        )
                        session.execute(text("""
                            UPDATE ports SET connection_info_preserved = :ci
                            WHERE switch_id = :sw_id AND port_no = :port_no
                        """), {
                            "ci": json.dumps(ci_data, ensure_ascii=False),
                            "sw_id": jrow.switch_id,
                            "port_no": jrow.port_no,
                        })

                    # Derive the oper_status to propagate: edge port 'down' → core
                    # port 'down'; anything else (up, unknown) → 'up'.
                    edge_oper = (jrow.edge_oper_status or 'unknown').strip().lower()
                    core_oper = 'down' if edge_oper == 'down' else 'up'

                    # Update (or fill in) the reverse-connection JSON on the core port.
                    core_port = session.execute(text("""
                        SELECT id, connection_info_preserved, oper_status FROM ports
                        WHERE switch_id = :sw_id AND port_no = :port_no
                    """), {"sw_id": core_sw_id, "port_no": core_port_no}).fetchone()
                    if core_port:
                        existing = (core_port[1] or '').strip()
                        if not existing.startswith('{'):
                            _apply_reverse_to_core_port(
                                session,
                                core_sw_id, core_port_no,
                                jrow.switch_id, jrow.switch_name, jrow.port_no
                            )
                            reverse_updated += 1
                        # Always sync oper_status from edge port to core port
                        if (core_port[2] or '').strip().lower() != core_oper:
                            session.execute(text("""
                                UPDATE ports SET oper_status = :oper
                                WHERE switch_id = :sw_id AND port_no = :port_no
                            """), {"oper": core_oper,
                                   "sw_id": core_sw_id,
                                   "port_no": core_port_no})

                    # Auto-register this edge fiber port in snmp_core_ports so that
                    # the alarm manager fires core_link_down when the port goes down.
                    # Only possible when we have the snmp_devices row for the edge switch.
                    if jrow.sd_id:
                        label_for_alarm = (
                            f"{core_sw_name} | {core_port_label}"
                            if core_port_label else core_sw_name
                        )
                        session.execute(text("""
                            MERGE INTO snmp_core_ports AS target
                            USING (SELECT :dev_id    AS device_id,
                                          :port_no   AS port_number,
                                          :core_name AS core_switch_name) AS src
                            ON (target.device_id = src.device_id AND target.port_number = src.port_number)
                            WHEN MATCHED THEN
                                UPDATE SET core_switch_name = src.core_switch_name
                            WHEN NOT MATCHED THEN
                                INSERT (device_id, port_number, core_switch_name)
                                VALUES (src.device_id, src.port_number, src.core_switch_name);
                        """), {
                            "dev_id": jrow.sd_id,
                            "port_no": jrow.port_no,
                            "core_name": label_for_alarm,
                        })

                except Exception:
                    pass

            if reverse_updated:
                session.commit()
                self.logger.info(
                    f"Core switch port reverse connections populated: {reverse_updated} port(s)"
                )
            else:
                # Commit any oper_status / snmp_core_ports updates even when no
                # new reverse connections were written.
                try:
                    session.commit()
                except Exception:
                    pass

            # ── Pass 3: Restore virtual_core JSON from snmp_core_ports ─────────
            # Edge ports registered in snmp_core_ports that LOST their JSON (e.g.
            # because LLDP stopped advertising the core switch system name and raw
            # port-description text was written instead) need to be rebuilt so the
            # UI shows the correct core switch connection and alarms fire correctly.
            # The core_switch_name column stores "CORESW-NAME | PortLabel" when
            # written by Pass 2.  Use that to reconstruct the virtual_core JSON.
            try:
                restore_rows = session.execute(text("""
                    SELECT sd.name  AS sw_name,
                           sw.id    AS sw_id,
                           p.id     AS port_id,
                           p.port_no,
                           p.connection_info_preserved AS ci,
                           cp.core_switch_name
                    FROM   snmp_core_ports cp
                    JOIN   snmp_devices sd ON sd.id = cp.device_id
                    JOIN   switches sw ON (sw.name = sd.name OR sw.ip = sd.ip_address)
                    JOIN   ports p ON (p.switch_id = sw.id AND p.port_no = cp.port_number)
                    WHERE  (p.connection_info_preserved IS NULL
                         OR p.connection_info_preserved = ''
                         OR p.connection_info_preserved NOT LIKE '{%')
                      AND  cp.core_switch_name LIKE '%|%'
                """)).fetchall()

                restore_count = 0
                for rrow in restore_rows:
                    try:
                        core_ref = (rrow.core_switch_name or '').strip()
                        if not core_ref:
                            continue
                        # Parse "CHAMADA-9606-CORESW-2 | TwentyFiveGigE2/1/0/35" format
                        core_parts      = [p.strip() for p in core_ref.split('|', 1)]
                        core_sw_name_h  = core_parts[0].strip() if core_parts else ''
                        core_port_label = core_parts[1].strip() if len(core_parts) > 1 else ''
                        if not core_sw_name_h or not core_port_label:
                            continue

                        # Look up the core switch by exact name first, then prefix
                        csw = session.execute(text(
                            "SELECT TOP 1 id, name FROM switches WHERE name = :n AND is_core = 1"
                        ), {"n": core_sw_name_h}).fetchone()
                        if not csw:
                            csw = session.execute(text(
                                "SELECT TOP 1 id, name FROM switches WHERE name LIKE :pat AND is_core = 1"
                            ), {"pat": f"{core_sw_name_h}%"}).fetchone()
                        if not csw:
                            continue

                        # Derive core_port_no from the port label using the
                        # two-module formula: (module-1)*48 + port_within_module
                        core_port_no = 0
                        lm = re.search(r'(?:GigE\d+)/(\d+)/0/(\d+)$', core_port_label, re.IGNORECASE)
                        if lm:
                            core_port_no = (int(lm.group(1)) - 1) * 48 + int(lm.group(2))
                        else:
                            lf = re.search(r'/(\d+)$', core_port_label)
                            if lf:
                                core_port_no = int(lf.group(1))
                        if not core_port_no:
                            continue

                        # Synthesize raw_lldp from core switch name + port label when
                        # connection_info_preserved was empty (e.g. first-time registration
                        # via snmp_core_ports before LLDP has ever been written).
                        raw_lldp_val = (rrow.ci or '').strip()
                        if not raw_lldp_val:
                            raw_lldp_val = (
                                f"{csw.name} | {core_port_label}"
                                if core_port_label else csw.name
                            )

                        new_ci = json.dumps({
                            "type":             "virtual_core",
                            "core_switch_id":   csw.id,
                            "core_switch_name": csw.name,
                            "core_port_no":     core_port_no,
                            "core_port_label":  core_port_label,
                            "raw_lldp":         raw_lldp_val,
                        }, ensure_ascii=False)

                        session.execute(text(
                            "UPDATE ports SET connection_info_preserved = :ci WHERE id = :id"
                        ), {"ci": new_ci, "id": rrow.port_id})

                        # Rebuild reverse JSON on the core switch port
                        _apply_reverse_to_core_port(
                            session,
                            csw.id, core_port_no,
                            rrow.sw_id, rrow.sw_name, rrow.port_no
                        )
                        restore_count += 1
                        self.logger.info(
                            f"Pass 3 restored: {rrow.sw_name} port {rrow.port_no} → "
                            f"{csw.name} port {core_port_no} ({core_port_label})"
                        )
                    except Exception as rre:
                        self.logger.warning(
                            f"Pass 3 restore error for port {getattr(rrow, 'port_no', '?')}: {rre}"
                        )

                if restore_count:
                    session.commit()
                    self.logger.info(
                        f"Pass 3: restored {restore_count} virtual_core JSON(s) from snmp_core_ports"
                    )
            except Exception as p3e:
                self.logger.error(f"Pass 3 (_update_core_port_connections) error: {p3e}")
                try:
                    session.rollback()
                except Exception:
                    pass

        except Exception as e:
            try:
                session.rollback()
            except Exception:
                pass
            self.logger.error(f"Error in _update_core_port_connections: {e}")
