"""
SNMP Polling Engine - Core polling logic for network devices.
Handles parallel polling of multiple devices.
"""

import logging
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from config.config_loader import Config, DeviceConfig
from core.snmp_client import SNMPClient
from core.database_manager import DatabaseManager
from core.alarm_manager import AlarmManager
from core.port_change_detector import PortChangeDetector
from vendors.factory import VendorFactory
from vendors.base import PortInfo, DeviceInfo
from models.database import DeviceStatus, PortStatus, SNMPDevice
from utils.logger import DeviceLoggerAdapter

# OID constants used directly in the polling engine
_OID_DOT1Q_PVID = '1.3.6.1.2.1.17.7.1.4.5.1.1'  # dot1qPvid (ifIndex → VLAN ID)


class DevicePoller:
    """Polls a single device and collects SNMP data."""
    
    def __init__(
        self,
        device_config: DeviceConfig,
        snmp_config: Any,
        db_manager: DatabaseManager,
        alarm_manager: AlarmManager,
        change_detector: PortChangeDetector
    ):
        """
        Initialize device poller.
        
        Args:
            device_config: Device configuration
            snmp_config: SNMP configuration
            db_manager: Database manager
            alarm_manager: Alarm manager
            change_detector: Port change detector
        """
        self.device_config = device_config
        self.snmp_config = snmp_config
        self.db_manager = db_manager
        self.alarm_manager = alarm_manager
        self.change_detector = change_detector
        
        # Setup logger with device context
        base_logger = logging.getLogger('snmp_worker.poller')
        self.logger = DeviceLoggerAdapter(
            base_logger,
            device_config.name,
            device_config.ip
        )
        
        # Create SNMP client
        self.snmp_client = self._create_snmp_client()
        
        # Get vendor mapper
        try:
            self.vendor_mapper = VendorFactory.get_mapper(
                device_config.vendor,
                device_config.model
            )
        except ValueError as e:
            self.logger.error(f"Failed to get vendor mapper: {e}")
            self.vendor_mapper = None
    
    def _create_snmp_client(self) -> SNMPClient:
        """Create SNMP client for device."""
        kwargs = {
            'host': self.device_config.ip,
            'version': self.device_config.snmp_version,
            'timeout': self.snmp_config.timeout,
            'retries': self.snmp_config.retries
        }
        
        if self.device_config.snmp_version == '2c':
            kwargs['community'] = self.device_config.community
        elif self.device_config.snmp_version == '3':
            v3_config = self.device_config.snmp_v3 or {}
            
            # ★★★ TEST SCRIPT'İ İLE AYNI PARAMETRELER ★★★
            kwargs.update({
                'username': v3_config.get('username', 'snmpuser'),
                'auth_protocol': v3_config.get('auth_protocol', 'SHA'),
                'auth_password': v3_config.get('auth_password', 'AuthPass123'),
                'priv_protocol': v3_config.get('priv_protocol', 'AES'),
                'priv_password': v3_config.get('priv_password', 'PrivPass123'),
                # Engine ID'yi boş bırak - otomatik keşif
                'engine_id': ''
            })
        
        return SNMPClient(**kwargs)
    
    def poll(self) -> Dict[str, Any]:
        """
        Poll device and return results.
        
        Returns:
            Dictionary containing poll results and status
        """
        start_time = time.time()
        result = {
            'device_name': self.device_config.name,
            'device_ip': self.device_config.ip,
            'success': False,
            'error': None,
            'duration_ms': 0,
            'device_info': None,
            'ports': []
        }
        
        if not self.vendor_mapper:
            result['error'] = "No vendor mapper available"
            return result
        
        try:
            # Test connection
            self.logger.info("Starting poll")
            if not self.snmp_client.test_connection():
                result['error'] = "Device unreachable"
                self.logger.error("Device unreachable")
                return result
            
            # Poll device information
            device_info = self._poll_device_info()
            result['device_info'] = device_info
            
            # Poll port information
            ports = self._poll_ports()
            result['ports'] = ports
            
            # Poll MAC addresses
            mac_table = self._poll_mac_table()
            
            # Associate MACs with ports
            self._associate_macs_with_ports(result['ports'], mac_table)
            
            result['success'] = True
            self.logger.info(f"Poll successful: {len(result['ports'])} ports collected")
        
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Poll failed: {e}")
        
        finally:
            result['duration_ms'] = (time.time() - start_time) * 1000
        
        return result
    
    def _poll_device_info(self) -> Optional[DeviceInfo]:
        """Poll device information."""
        try:
            oids = self.vendor_mapper.get_device_info_oids()
            snmp_data = self.snmp_client.get_multiple(oids)
            device_info = self.vendor_mapper.parse_device_info(snmp_data)
            return device_info
        except Exception as e:
            self.logger.error(f"Failed to poll device info: {e}")
            return None
    
    def _poll_ports(self) -> List[PortInfo]:
        """Poll port information."""
        try:
            oid_prefixes = self.vendor_mapper.get_port_info_oids()
            
            # Walk all OID prefixes
            snmp_data = {}
            for oid_prefix in oid_prefixes:
                results = self.snmp_client.get_bulk(oid_prefix, self.snmp_config.max_bulk_size)
                for oid, value in results:
                    snmp_data[oid] = value
            
            # Fetch individual OIDs that don't support WALK (e.g. Cisco vmVlan).
            # PHP does: for ($i=1;$i<=28;$i++) $vmVlan = $snmp->get('...68.1.2.2.1.2.'.$i);
            # We mirror that pattern exactly: one GET per OID to avoid PDU-size rejection.
            individual_oids = self.vendor_mapper.get_port_get_oids()
            for oid in individual_oids:
                result = self.snmp_client.get(oid)
                if result:
                    oid_str, value = result
                    snmp_data[oid_str] = value
            
            # Parse port info
            ports = self.vendor_mapper.parse_port_info(snmp_data)
            return ports
        except Exception as e:
            self.logger.error(f"Failed to poll ports: {e}")
            return []
    
    def _poll_mac_table(self) -> Dict[int, List[str]]:
        """Poll MAC address table."""
        try:
            # For Cisco IOS-XE mappers that support per-VLAN context MAC collection
            # (C9200L / C9300L), prefer that method — it yields real MACs whereas
            # the empty-context dot1d walk returns nothing on these firmware versions.
            if hasattr(self.vendor_mapper, 'collect_mac_with_vlan_contexts'):
                # Gather unique VLANs from already-polled port data so we only
                # query the contexts that are actually in use.
                active_vlans: List[int] = [1]  # always include VLAN 1
                try:
                    # vendor_mapper._if_to_port is populated by parse_port_info;
                    # PVID data is in the mapper's internal pvid/cisco_vlan maps.
                    # We re-walk the port list indirectly through a fresh PVID
                    # query or fall back to querying the full range.
                    pvid_results = self.snmp_client.get_bulk(
                        _OID_DOT1Q_PVID,  # dot1qPvid
                        self.snmp_config.max_bulk_size
                    )
                    seen_vlans = {1}
                    for oid, val in pvid_results:
                        try:
                            v = int(str(val))
                            if 1 <= v <= 4094:
                                seen_vlans.add(v)
                        except Exception:
                            pass
                    active_vlans = sorted(seen_vlans)
                except Exception:
                    pass  # fall back to default [1]

                mac_table = self.vendor_mapper.collect_mac_with_vlan_contexts(
                    self.snmp_client, active_vlans
                )
                if mac_table:
                    return mac_table
                # If VLAN-context walk returned nothing, fall through to
                # the standard walk (backward-compatible).

            oid_prefixes = self.vendor_mapper.get_mac_table_oids()

            # Walk MAC table OIDs
            snmp_data = {}
            for oid_prefix in oid_prefixes:
                results = self.snmp_client.get_bulk(oid_prefix, self.snmp_config.max_bulk_size)
                for oid, value in results:
                    snmp_data[oid] = value

            # Parse MAC table
            mac_table = self.vendor_mapper.parse_mac_table(snmp_data)
            return mac_table
        except Exception as e:
            self.logger.error(f"Failed to poll MAC table: {e}")
            return {}
    
    def _associate_macs_with_ports(
        self,
        ports: List[PortInfo],
        mac_table: Dict[int, List[str]]
    ) -> None:
        """Associate MAC addresses with ports."""
        for port in ports:
            if port.port_number in mac_table:
                macs = mac_table[port.port_number]
                if macs:
                    port.mac_address = macs[0] if len(macs) == 1 else None
                    # Store all MACs for later use if needed
                    if not hasattr(port, '_all_macs'):
                        port._all_macs = macs
    
    def save_to_database(self, poll_result: Dict[str, Any]) -> None:
        """
        Save poll results to database.
        
        Args:
            poll_result: Poll results dictionary
        """
        with self.db_manager.session_scope() as session:
            # Build kwargs — include SNMPv3 credentials so snmp_devices table
            # holds them for LLDP collection and other services (autosync, etc.)
            device_kwargs = dict(
                snmp_version=self.device_config.snmp_version,
                snmp_community=self.device_config.community if self.device_config.snmp_version == '2c' else None,
                enabled=self.device_config.enabled,
            )
            if self.device_config.snmp_version == '3' and self.device_config.snmp_v3:
                v3 = self.device_config.snmp_v3
                device_kwargs.update(
                    snmp_v3_username=v3.get('username'),
                    snmp_v3_auth_protocol=v3.get('auth_protocol'),
                    snmp_v3_auth_password=v3.get('auth_password'),
                    snmp_v3_priv_protocol=v3.get('priv_protocol'),
                    snmp_v3_priv_password=v3.get('priv_password'),
                )

            # Get or create device
            device = self.db_manager.get_or_create_device(
                session,
                name=self.device_config.name,
                ip_address=self.device_config.ip,
                vendor=self.device_config.vendor,
                model=self.device_config.model,
                **device_kwargs
            )
            
            # Update device status
            if poll_result['success']:
                device_info = poll_result.get('device_info')
                self.db_manager.update_device_status(
                    session,
                    device,
                    DeviceStatus.ONLINE,
                    system_description=device_info.system_description if device_info else None,
                    system_uptime=device_info.system_uptime if device_info else None,
                    total_ports=device_info.total_ports if device_info else None
                )
                
                # Check device reachability alarm
                self.alarm_manager.check_device_reachability(session, device, True)
            else:
                self.db_manager.update_device_status(
                    session,
                    device,
                    DeviceStatus.UNREACHABLE if poll_result.get('error') == 'Device unreachable' else DeviceStatus.ERROR
                )
                
                # Check device reachability alarm
                self.alarm_manager.check_device_reachability(session, device, False)
            
            # Save polling data
            self.db_manager.save_polling_data(
                session,
                device,
                success=poll_result['success'],
                poll_duration_ms=poll_result['duration_ms'],
                error_message=poll_result.get('error')
            )
            
            # Save port data
            if poll_result['success']:
                for port in poll_result['ports']:
                    # Convert status strings to enums
                    admin_status = PortStatus.UP if port.admin_status == 'up' else PortStatus.DOWN
                    oper_status = PortStatus.UP if port.oper_status == 'up' else PortStatus.DOWN
                    
                    # Save port status
                    port_status_data = self.db_manager.save_port_status(
                        session,
                        device,
                        port_number=port.port_number,
                        admin_status=admin_status,
                        oper_status=oper_status,
                        port_name=port.port_name,
                        port_alias=port.port_alias,
                        port_type=port.port_type,
                        port_speed=port.port_speed,
                        port_mtu=port.port_mtu,
                        mac_address=port.mac_address,
                        vlan_id=port.vlan_id,
                        in_octets=port.in_octets,
                        out_octets=port.out_octets,
                        in_errors=port.in_errors,
                        out_errors=port.out_errors,
                        in_discards=port.in_discards,
                        out_discards=port.out_discards,
                    )
                    
                    # Update operational status in legacy ports table (Issue #2 fix)
                    # This preserves connection data when port goes down
                    try:
                        self.db_manager.update_port_operational_status(
                            session,
                            device,
                            port.port_number,
                            port.oper_status  # 'up' or 'down'
                        )
                    except Exception as e:
                        self.logger.debug(f"Could not update legacy port status: {e}")
                    
                    # Detect and record changes
                    try:
                        changes = self.change_detector.detect_and_record_changes(
                            session,
                            device,
                            port_status_data
                        )
                        if changes:
                            self.logger.info(f"Detected {len(changes)} change(s) on port {port.port_number}")
                    except Exception as e:
                        self.logger.error(f"Error detecting changes on port {port.port_number}: {e}")
                    
                    # Check for port status alarms
                    self.alarm_manager.check_port_status(
                        session,
                        device,
                        port.port_number,
                        port.port_name,
                        admin_status,
                        oper_status
                    )


class PollingEngine:
    """Main polling engine that manages polling of all devices."""
    
    def __init__(
        self,
        config: Config,
        db_manager: DatabaseManager,
        alarm_manager: AlarmManager
    ):
        """
        Initialize polling engine.
        
        Args:
            config: Configuration object
            db_manager: Database manager
            alarm_manager: Alarm manager
        """
        self.config = config
        self.db_manager = db_manager
        self.alarm_manager = alarm_manager
        self.change_detector = PortChangeDetector(db_manager, alarm_manager)
        self.logger = logging.getLogger('snmp_worker.engine')
        
        # Create device pollers
        self.pollers: List[DevicePoller] = []
        for device_config in config.devices:
            if device_config.enabled:
                poller = DevicePoller(
                    device_config,
                    config.snmp,
                    db_manager,
                    alarm_manager,
                    self.change_detector
                )
                self.pollers.append(poller)
        
        self.logger.info(f"Polling engine initialized with {len(self.pollers)} devices")
    
    def poll_all_devices(self) -> List[Dict[str, Any]]:
        """
        Poll all devices in parallel.
        
        Returns:
            List of poll results
        """
        results = []
        
        if not self.pollers:
            self.logger.warning("No enabled devices to poll")
            return results
        
        self.logger.info(f"Polling {len(self.pollers)} devices")
        
        with ThreadPoolExecutor(max_workers=self.config.polling.max_workers) as executor:
            # Submit all poll tasks
            future_to_poller = {
                executor.submit(poller.poll): poller
                for poller in self.pollers
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_poller):
                poller = future_to_poller[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Save to database
                    poller.save_to_database(result)
                    
                except Exception as e:
                    self.logger.error(f"Failed to poll device {poller.device_config.name}: {e}")
                    results.append({
                        'device_name': poller.device_config.name,
                        'device_ip': poller.device_config.ip,
                        'success': False,
                        'error': str(e)
                    })
        
        # Log summary
        successful = sum(1 for r in results if r['success'])
        self.logger.info(f"Poll cycle complete: {successful}/{len(results)} successful")
        
        return results