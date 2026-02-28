"""
Vendor abstraction layer for SNMP OID mapping.
Provides a unified interface for different vendor implementations.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class PortInfo:
    """Port information structure."""
    port_number: int
    port_name: str
    port_alias: str
    admin_status: str
    oper_status: str
    port_type: str
    port_speed: int
    port_mtu: int
    mac_address: Optional[str] = None
    vlan_id: Optional[int] = None


@dataclass
class DeviceInfo:
    """Device information structure."""
    system_description: str
    system_name: str
    system_uptime: int
    total_ports: int


class VendorOIDMapper(ABC):
    """
    Abstract base class for vendor-specific OID mappings.
    Each vendor should implement this interface.
    """
    
    # Standard MIB-II OIDs (common across vendors)
    OID_SYSTEM = "1.3.6.1.2.1.1"
    OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
    OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
    OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
    OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
    OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
    OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
    
    # Interface MIB OIDs
    OID_IF_NUMBER = "1.3.6.1.2.1.2.1.0"
    OID_IF_TABLE = "1.3.6.1.2.1.2.2.1"
    OID_IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
    OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
    OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
    OID_IF_MTU = "1.3.6.1.2.1.2.2.1.4"
    OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
    OID_IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
    OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
    OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
    OID_IF_LAST_CHANGE = "1.3.6.1.2.1.2.2.1.9"
    
    # IF-MIB extensions
    OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
    OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
    OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
    
    # Bridge MIB (for MAC address tables)
    OID_DOT1D_BASE_PORT = "1.3.6.1.2.1.17.1.4.1.2"
    OID_DOT1D_TP_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"
    OID_DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
    
    # VLAN MIB
    OID_VLAN_TRUNK_PORT_VLANS = "1.3.6.1.4.1.9.9.46.1.6.1.1.4"
    
    def __init__(self):
        """Initialize vendor mapper."""
        self.vendor_name = "generic"
        self.model_name = "generic"
    
    @abstractmethod
    def get_device_info_oids(self) -> List[str]:
        """
        Get OIDs for device information.
        
        Returns:
            List of OIDs to query
        """
        pass
    
    @abstractmethod
    def parse_device_info(self, snmp_data: Dict[str, Any]) -> DeviceInfo:
        """
        Parse device information from SNMP data.
        
        Args:
            snmp_data: Dictionary of OID -> value
            
        Returns:
            DeviceInfo object
        """
        pass
    
    @abstractmethod
    def get_port_info_oids(self) -> List[str]:
        """
        Get OIDs for port information.
        
        Returns:
            List of OID prefixes to walk
        """
        pass
    
    @abstractmethod
    def parse_port_info(self, snmp_data: Dict[str, Any]) -> List[PortInfo]:
        """
        Parse port information from SNMP data.
        
        Args:
            snmp_data: Dictionary of OID -> value
            
        Returns:
            List of PortInfo objects
        """
        pass
    
    def get_port_get_oids(self, num_ports: int = 28) -> List[str]:
        """
        Get list of individual OIDs to fetch via GET (not walk).
        Override in vendor subclasses for OIDs that don't support GETBULK/GETNEXT
        but do respond to per-instance GET (e.g. Cisco enterprise OIDs).
        
        Returns:
            Flat list of fully-qualified OIDs (with instance suffix)
        """
        return []

    def get_mac_table_oids(self) -> List[str]:
        """
        Get OIDs for MAC address table.
        
        Returns:
            List of OID prefixes to walk
        """
        return [
            self.OID_DOT1D_TP_FDB_ADDRESS,
            self.OID_DOT1D_TP_FDB_PORT,
            self.OID_DOT1D_BASE_PORT
        ]
    
    def parse_mac_table(self, snmp_data: Dict[str, Any]) -> Dict[int, List[str]]:
        """
        Parse MAC address table from SNMP data.
        
        Args:
            snmp_data: Dictionary of OID -> value
            
        Returns:
            Dictionary mapping port number to list of MAC addresses
        """
        mac_to_bridge_port = {}
        bridge_port_to_if_index = {}
        
        # Parse MAC to bridge port mapping
        for oid, value in snmp_data.items():
            if self.OID_DOT1D_TP_FDB_ADDRESS in oid:
                # Extract MAC address from OID
                mac_parts = oid.split('.')[-6:]
                mac = ':'.join([f'{int(x):02x}' for x in mac_parts])
                mac_to_bridge_port[mac] = None
            elif self.OID_DOT1D_TP_FDB_PORT in oid:
                mac_parts = oid.split('.')[-6:]
                mac = ':'.join([f'{int(x):02x}' for x in mac_parts])
                bridge_port = int(value)
                mac_to_bridge_port[mac] = bridge_port
        
        # Parse bridge port to interface index mapping
        for oid, value in snmp_data.items():
            if self.OID_DOT1D_BASE_PORT in oid:
                bridge_port = int(oid.split('.')[-1])
                if_index = int(value)
                bridge_port_to_if_index[bridge_port] = if_index
        
        # Create final mapping: port -> [MACs]
        port_mac_map: Dict[int, List[str]] = {}
        for mac, bridge_port in mac_to_bridge_port.items():
            if bridge_port and bridge_port in bridge_port_to_if_index:
                if_index = bridge_port_to_if_index[bridge_port]
                if if_index not in port_mac_map:
                    port_mac_map[if_index] = []
                port_mac_map[if_index].append(mac)
        
        return port_mac_map
    
    @staticmethod
    def status_to_string(status_code: int) -> str:
        """
        Convert SNMP status code to string.
        
        Args:
            status_code: Status code from SNMP
            
        Returns:
            Status string
        """
        status_map = {
            1: "up",
            2: "down",
            3: "testing",
            4: "unknown",
            5: "dormant",
            6: "notPresent",
            7: "lowerLayerDown"
        }
        return status_map.get(status_code, "unknown")
