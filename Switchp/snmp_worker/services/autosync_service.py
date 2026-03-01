"""
Automatic synchronization service.
Syncs SNMP worker data to main switches table automatically.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import text, func

from models.database import SNMPDevice, PortStatusData
from core.database_manager import DatabaseManager
from core.snmp_client import SNMPClient

# VLAN ID → port type mapping (same mapping as the UI VLAN_TYPE_MAP in index.php)
VLAN_TYPE_MAP: Dict[int, str] = {
    50: 'DEVICE',
    254: 'SERVER',
    70: 'AP',
    80: 'KAMERA',
    120: 'OTOMASYON',
    130: 'IPTV',
    140: 'SANTRAL',
}


class AutoSyncService:
    """
    Automatically synchronizes SNMP worker data to main switches database.
    This service runs after each polling cycle to keep the main database updated.
    """
    
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
            
            if synced_count > 0:
                self.logger.info(
                    f"Auto sync complete: {synced_count} device(s) synchronized, "
                    f"{error_count} error(s)"
                )
            
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
        # Check if switch exists in main table — look up by IP first, then by name.
        # Searching by name as a fallback prevents a duplicate-key IntegrityError
        # when the switch was already added (manually or by a previous autosync run)
        # with a different IP address stored in the switches table.
        result = session.execute(
            text("SELECT id FROM switches WHERE ip = :ip"),
            {"ip": device.ip_address}
        ).fetchone()

        if result is None:
            result = session.execute(
                text("SELECT id FROM switches WHERE name = :name"),
                {"name": device.name}
            ).fetchone()

        if result:
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

        # Collect LLDP neighbor data for fiber ports
        lldp_neighbors: Dict[int, Dict[str, str]] = {}
        try:
            snmp_client = self._create_snmp_client_for_device(device)
            if snmp_client:
                lldp_neighbors = snmp_client.get_lldp_neighbors()
                if lldp_neighbors:
                    self.logger.debug(
                        f"LLDP: found {len(lldp_neighbors)} neighbor(s) for {device.name}"
                    )
        except Exception as e:
            self.logger.debug(f"Could not collect LLDP data for {device.name}: {e}")

        ports_synced = 0
        
        for port in latest_ports:
            try:
                # Check if port exists – also read existing device/ip to avoid wiping user data
                result = session.execute(
                    text("SELECT id, type, device, ip FROM ports WHERE switch_id = :switch_id AND port_no = :port_no"),
                    {"switch_id": switch_id, "port_no": port.port_number}
                ).fetchone()

                is_up = port.oper_status.value == 'up' and port.admin_status.value == 'up'
                oper_status_str = 'up' if is_up else 'down'
                mac_address = port.mac_address if port.mac_address else ''

                # Determine the SNMP-provided port label.
                # CBS350 reports ifAlias (port_alias) only when the admin sets a
                # description on the port; ifName (port_name) is always "GEX".
                # Prefer alias; fall back to name only for new (INSERT) rows.
                snmp_alias = (port.port_alias or '').strip()
                snmp_name  = (port.port_name  or '').strip()

                meaningful_types = {
                    'DEVICE', 'SERVER', 'AP', 'KAMERA', 'IPTV',
                    'OTOMASYON', 'SANTRAL', 'FIBER', 'ETHERNET', 'HUB'
                }

                # Effective VLAN: use what Python SNMP directly detected this cycle.
                # With lookupMib=False, Python reliably detects real VLANs (50, 120, 130, etc.).
                # If vlan_id=1 or None (SNMP walk failed), effective_vlan=None → preserve type.
                effective_vlan = port.vlan_id if (port.vlan_id and port.vlan_id > 1) else None

                # Determine port type:
                # 1. If port is DOWN → keep existing meaningful type, oper_status='down'
                # 2. If port is UP + VLAN known → mapped device type (auto-correct user type)
                # 3. If port is UP + VLAN unknown (not in map) → "VLAN X" (red in UI)
                # 4. If port is UP + no VLAN detected at all → preserve existing or 'DEVICE'
                if not is_up:
                    existing_type = result[1] if result else None
                    if existing_type and (existing_type in meaningful_types or
                                          existing_type.startswith('VLAN ')):
                        port_type = existing_type  # preserve
                    else:
                        port_type = 'EMPTY'
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

                # Build LLDP connection info for fiber ports
                lldp_info: Optional[str] = None
                if port.port_number >= fiber_port_min and port.port_number in lldp_neighbors:
                    neighbor = lldp_neighbors[port.port_number]
                    sys_name = neighbor.get('system_name', '').strip()
                    port_desc = neighbor.get('port_desc', '').strip()
                    chassis_id = neighbor.get('chassis_id', '').strip()
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
                        #   - Only overwrite device if admin set a real SNMP alias (not just "GEX")
                        #   - Never clear the IP address that the user manually entered
                        existing_device = (result[2] or '').strip() if result else ''
                        # Use SNMP alias only if it's a real description (not raw port name like 'GE20')
                        use_alias = snmp_alias and not snmp_alias.upper().startswith('GE')
                        new_device = snmp_alias if use_alias else (existing_device or snmp_name)
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
                                "mac": mac_address,
                                "id": port_id
                            }
                        )

                        # Fire VLAN change alarm when SNMP-derived type differs from stored type.
                        # This catches both: switch admin changed VLAN config, and UI type mismatch.
                        if (effective_vlan and effective_vlan > 1
                                and existing_type and existing_type != port_type
                                and existing_type in meaningful_types
                                and port_type in meaningful_types):
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
                                    alarm.new_value = port_type
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

                    # Write LLDP info to connection_info_preserved for fiber ports
                    if lldp_info is not None:
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
                            "mac": mac_address,
                            "conn_info": lldp_info or ''
                        }
                    )
                
                ports_synced += 1
                
            except Exception as e:
                self.logger.warning(f"Error syncing port {port.port_number} on {device.name}: {e}")
        
        if ports_synced > 0:
            self.logger.debug(f"Synced {ports_synced} port(s) for {device.name}")

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
