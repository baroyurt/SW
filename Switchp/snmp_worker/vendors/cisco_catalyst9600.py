"""
Cisco Catalyst 9600 OID mapper.
Optimized for Cisco Catalyst 9600 Core Switch.
"""

from typing import Dict, List, Any
from .base import VendorOIDMapper, DeviceInfo, PortInfo


class CiscoCatalyst9600Mapper(VendorOIDMapper):
    """OID mapper for Cisco Catalyst 9600 switches."""
    
    # Cisco-specific OIDs
    OID_CISCO_ENV_MON = "1.3.6.1.4.1.9.9.13"  # Environmental monitoring
    OID_CISCO_CPU = "1.3.6.1.4.1.9.9.109.1.1.1.1.8"  # CPU usage
    OID_CISCO_MEMORY = "1.3.6.1.4.1.9.9.48.1.1.1"  # Memory usage
    OID_CISCO_VLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"  # VLAN info
    
    def __init__(self):
        """Initialize Cisco Catalyst 9600 mapper."""
        super().__init__()
        self.vendor_name = "cisco"
        self.model_name = "catalyst9600"
    
    def get_device_info_oids(self) -> List[str]:
        """Get OIDs for device information."""
        return [
            self.OID_SYS_DESCR,
            self.OID_SYS_NAME,
            self.OID_SYS_UPTIME,
            self.OID_IF_NUMBER,
            self.OID_SYS_CONTACT,
            self.OID_SYS_LOCATION
        ]
    
    def parse_device_info(self, snmp_data: Dict[str, Any]) -> DeviceInfo:
        """Parse device information from SNMP data."""
        sys_descr = str(snmp_data.get(self.OID_SYS_DESCR, "Unknown"))
        sys_name = str(snmp_data.get(self.OID_SYS_NAME, "Unknown"))
        sys_uptime = int(snmp_data.get(self.OID_SYS_UPTIME, 0))
        if_number = int(snmp_data.get(self.OID_IF_NUMBER, 0))
        
        return DeviceInfo(
            system_description=sys_descr,
            system_name=sys_name,
            system_uptime=sys_uptime,
            total_ports=if_number
        )
    
    def get_port_info_oids(self) -> List[str]:
        """Get OIDs for port information."""
        return [
            self.OID_IF_DESCR,
            self.OID_IF_NAME,
            self.OID_IF_ALIAS,
            self.OID_IF_TYPE,
            self.OID_IF_MTU,
            self.OID_IF_SPEED,
            self.OID_IF_HIGH_SPEED,
            self.OID_IF_ADMIN_STATUS,
            self.OID_IF_OPER_STATUS,
            self.OID_IF_PHYS_ADDRESS
        ]
    
    def parse_port_info(self, snmp_data: Dict[str, Any]) -> List[PortInfo]:
        """
        Parse port information from SNMP data.
        
        For Catalyst 9600, we filter only physical ethernet ports.
        """
        ports = {}
        
        # Parse interface descriptions to get port numbers
        for oid, value in snmp_data.items():
            if self.OID_IF_DESCR in oid and not oid.endswith(self.OID_IF_DESCR):
                if_index = int(oid.split('.')[-1])
                descr = str(value)
                
                # Filter for physical ethernet ports
                # Catalyst 9600 uses names like "GigabitEthernet1/0/1"
                if any(x in descr for x in ['GigabitEthernet', 'TenGigabitEthernet', 'FortyGigabitEthernet']):
                    ports[if_index] = {
                        'port_number': if_index,
                        'port_name': descr,
                        'port_alias': '',
                        'admin_status': 'unknown',
                        'oper_status': 'unknown',
                        'port_type': '',
                        'port_speed': 0,
                        'port_mtu': 0,
                        'mac_address': None,
                        'vlan_id': None
                    }
        
        # Parse interface names
        for oid, value in snmp_data.items():
            if self.OID_IF_NAME in oid and not oid.endswith(self.OID_IF_NAME):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['port_name'] = str(value)
        
        # Parse interface aliases (descriptions)
        for oid, value in snmp_data.items():
            if self.OID_IF_ALIAS in oid and not oid.endswith(self.OID_IF_ALIAS):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['port_alias'] = str(value)
        
        # Parse admin status
        for oid, value in snmp_data.items():
            if self.OID_IF_ADMIN_STATUS in oid and not oid.endswith(self.OID_IF_ADMIN_STATUS):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['admin_status'] = self.status_to_string(int(value))
        
        # Parse operational status
        for oid, value in snmp_data.items():
            if self.OID_IF_OPER_STATUS in oid and not oid.endswith(self.OID_IF_OPER_STATUS):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['oper_status'] = self.status_to_string(int(value))
        
        # Parse interface type
        for oid, value in snmp_data.items():
            if self.OID_IF_TYPE in oid and not oid.endswith(self.OID_IF_TYPE):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['port_type'] = str(value)
        
        # Parse speed (prefer high-speed if available)
        for oid, value in snmp_data.items():
            if self.OID_IF_HIGH_SPEED in oid and not oid.endswith(self.OID_IF_HIGH_SPEED):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    # High speed is in Mbps, convert to bps
                    ports[if_index]['port_speed'] = int(value) * 1000000
            elif self.OID_IF_SPEED in oid and not oid.endswith(self.OID_IF_SPEED):
                if_index = int(oid.split('.')[-1])
                if if_index in ports and ports[if_index]['port_speed'] == 0:
                    ports[if_index]['port_speed'] = int(value)
        
        # Parse MTU
        for oid, value in snmp_data.items():
            if self.OID_IF_MTU in oid and not oid.endswith(self.OID_IF_MTU):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['port_mtu'] = int(value)
        
        # Convert to PortInfo objects
        port_list = []
        for port_data in ports.values():
            port_list.append(PortInfo(**port_data))
        
        return port_list
