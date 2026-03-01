"""
Cisco CBS350 OID mapper.
Optimized for Cisco CBS350 Access Switch (Small Business).
"""

import logging
import binascii
from typing import Dict, List, Any, Optional
from .base import VendorOIDMapper, DeviceInfo, PortInfo

_log = logging.getLogger(__name__)

def _octetstring_to_bytes(value) -> bytes:
    """
    Convert a pysnmp OctetString (or plain bytes) to raw bytes.

    Conversion order (matches vlan_oid_test_v2.py which is proven to work):
      1. Already bytes → return as-is
      2. asOctets()   → most reliable for pysnmp OctetString
      3. prettyPrint() → colon-separated or 0x-prefixed hex string → unhexlify
      4. asNumbers()  → tuple of ints → bytes
      5. bytes(bytearray(value)) → last resort
    """
    if isinstance(value, bytes):
        return value
    # asOctets() — most reliable (used in v2 test script first)
    if hasattr(value, 'asOctets'):
        try:
            raw = value.asOctets()
            return raw if isinstance(raw, bytes) else bytes(raw)
        except Exception:
            pass
    # prettyPrint() gives "0xAABBCC..." or "aa:bb:cc:..."
    if hasattr(value, 'prettyPrint'):
        try:
            s = value.prettyPrint()
            clean = s.replace('0x', '').replace(':', '').replace(' ', '')
            if clean and all(c in '0123456789abcdefABCDEF' for c in clean) and len(clean) % 2 == 0:
                return binascii.unhexlify(clean)
        except Exception:
            pass
    if hasattr(value, 'asNumbers'):
        try:
            return bytes(bytearray(value.asNumbers()))
        except Exception:
            pass
    try:
        return bytes(bytearray(value))
    except Exception:
        pass
    return b''


class CiscoCBS350Mapper(VendorOIDMapper):
    """OID mapper for Cisco CBS350 switches."""
    
    def __init__(self):
        """Initialize Cisco CBS350 mapper."""
        super().__init__()
        self.vendor_name = "cisco"
        self.model_name = "cbs350"
    
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
        
        # For CBS350-24FP-4G: 24 PoE ports + 4 SFP ports = 28 physical ports
        # Don't use if_number as it includes virtual interfaces
        # Instead, count actual physical ethernet ports from interface descriptions
        physical_port_count = 0
        for oid, value in snmp_data.items():
            if self.OID_IF_DESCR in oid and not oid.endswith(self.OID_IF_DESCR):
                descr = str(value).lower()
                # Count only physical ethernet ports (GigabitEthernet / GE prefix)
                # CBS350-24FP has ports 1-28: gi1-gi24 (PoE) + gi25-gi28 (SFP)
                # CBS350 may also report ports as "GE1"-"GE28"
                if descr.startswith(('gi', 'ge', 'gigabit', 'ethernet', 'fa', 'te')):
                    if not any(x in descr for x in ['vlan', 'management', 'null', 'loopback', 'port-channel']):
                        physical_port_count += 1
        
        # If we couldn't count ports, fall back to a safe default for CBS350-24FP
        # Model typically indicates the port count (24 in CBS350-24FP)
        if physical_port_count == 0:
            if '24' in sys_descr:
                physical_port_count = 28  # 24 PoE + 4 SFP
            else:
                physical_port_count = int(snmp_data.get(self.OID_IF_NUMBER, 0))
        
        return DeviceInfo(
            system_description=sys_descr,
            system_name=sys_name,
            system_uptime=sys_uptime,
            total_ports=physical_port_count
        )
    
    def get_port_info_oids(self) -> List[str]:
        """Get OIDs for port information (these are walked via GETBULK)."""
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
            self.OID_IF_PHYS_ADDRESS,
            self.OID_IF_HC_IN_OCTETS,
            self.OID_IF_HC_OUT_OCTETS,
            self.OID_IF_IN_ERRORS,
            self.OID_IF_OUT_ERRORS,
            self.OID_IF_IN_DISCARDS,
            self.OID_IF_OUT_DISCARDS,
            '1.3.6.1.2.1.17.7.1.4.2.1.5',    # dot1qVlanStaticUntaggedPorts – access ports
            '1.3.6.1.2.1.17.7.1.4.2.1.4',    # dot1qVlanStaticEgressPorts – trunk detection
        ]

    def get_port_get_oids(self, num_ports: int = 28) -> List[str]:
        """No individual per-port GETs needed — untagged/egress masks cover all VLANs."""
        return []
    
    def parse_port_info(self, snmp_data: Dict[str, Any]) -> List[PortInfo]:
        """
        Parse port information from SNMP data.
        
        VLAN detection uses the EXACT SAME approach as sh_int_status_snmp.py
        (which is proven to work): store raw OctetString mask values keyed by
        VLAN ID, then call _determine_vlan(ifIndex, ...) per port.
        """
        ports = {}

        # ── VLAN PARSING (exact sh_int_status_snmp.py approach) ─────────────
        # Store raw mask values per VLAN ID (same as script's untagged_raw/egress_raw).
        # Then per-port: check membership via bitmap directly using ifIndex as port position.
        # CBS350: ifIndex 1-28 = GE1-GE28 = bitmap bit positions 1-28.

        def _bitmap_ports(mask_val, num_ports: int = 28) -> set:
            """OctetString bitmap → set of 1-based port numbers (same as script)."""
            raw = _octetstring_to_bytes(mask_val)
            if not raw:
                return set()
            result = set()
            for i in range(1, num_ports + 1):
                byte_pos = (i - 1) // 8
                bit_pos  = 7 - ((i - 1) % 8)
                if byte_pos < len(raw) and (raw[byte_pos] >> bit_pos) & 1:
                    result.add(i)
            return result

        # Collect raw mask values (script: untagged_raw / egress_raw dicts)
        OID_UNTAGGED = '1.3.6.1.2.1.17.7.1.4.2.1.5'
        OID_EGRESS   = '1.3.6.1.2.1.17.7.1.4.2.1.4'

        untagged_raw: Dict[int, Any] = {}  # vlan_id -> raw OctetString
        egress_raw:   Dict[int, Any] = {}  # vlan_id -> raw OctetString

        for oid, value in snmp_data.items():
            if oid.startswith(OID_UNTAGGED + '.') or 'dot1qVlanStaticUntaggedPorts' in oid:
                try:
                    untagged_raw[int(oid.split('.')[-1])] = value
                except Exception:
                    pass

        for oid, value in snmp_data.items():
            if oid.startswith(OID_EGRESS + '.') or 'dot1qVlanStaticEgressPorts' in oid:
                try:
                    egress_raw[int(oid.split('.')[-1])] = value
                except Exception:
                    pass

        # Pre-compute port sets once per VLAN (avoids re-parsing bitmaps per port).
        # untagged_sets[vlan_id] = {port, ...}  /  egress_sets[vlan_id] = {port, ...}
        untagged_sets: Dict[int, set] = {v: _bitmap_ports(m) for v, m in untagged_raw.items()}
        egress_sets:   Dict[int, set] = {v: _bitmap_ports(m) for v, m in egress_raw.items()}

        _log.debug(
            f"VLAN sources: snmp_data_keys={len(snmp_data)}, "
            f"untagged_vlans={len(untagged_raw)}, egress_vlans={len(egress_raw)}"
        )

        def _determine_vlan(port_idx: int) -> Optional[int]:
            """
            Determine VLAN for a port by ifIndex.
            Same logic as sh_int_status_snmp.py determine_vlan() -- uses pre-computed sets.
              - untagged, non-VLAN-1 -> access VLAN (int)
              - tagged-only (trunk)   -> None (preserves FIBER type in autosync)
              - VLAN 1 only           -> 1
              - unknown               -> None
            """
            untagged_vlans: set = {v for v, s in untagged_sets.items() if port_idx in s}
            tagged_vlans:   set = {v for v, s in egress_sets.items()   if port_idx in s and v not in untagged_vlans}

            real_untagged = untagged_vlans - {1}
            real_tagged   = tagged_vlans   - {1}

            if real_tagged:
                return None              # trunk port (fiber/uplink)
            elif real_untagged:
                return sorted(real_untagged)[0]  # access VLAN
            elif 1 in untagged_vlans:
                return 1                 # default VLAN 1
            else:
                return None              # unknown

        # Parse interface descriptions to get port numbers
        for oid, value in snmp_data.items():
            if oid.startswith(self.OID_IF_DESCR + '.'):
                if_index = int(oid.split('.')[-1])
                descr = str(value)
                
                # Filter for physical ethernet ports.
                # CBS350 uses "GE1"–"GE28" (prefixed "ge"), "gi1"/"gi2",
                # or "GigabitEthernet1/0/1".  Use startswith to avoid false
                # matches like 'aggregate' that contain 'ge' as a substring.
                dl = descr.lower()
                if dl.startswith(('gi', 'ge', 'gigabit', 'ethernet', 'fa', 'te')):
                    # Skip management, virtual interfaces, and port-channels
                    if not any(x in dl for x in ['vlan', 'management', 'null', 'loopback', 'port-channel']):
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
            if oid.startswith(self.OID_IF_NAME + '.'):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['port_name'] = str(value)
        
        # Parse interface aliases (descriptions)
        for oid, value in snmp_data.items():
            if oid.startswith(self.OID_IF_ALIAS + '.'):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['port_alias'] = str(value)
        
        # Parse admin status
        for oid, value in snmp_data.items():
            if oid.startswith(self.OID_IF_ADMIN_STATUS + '.'):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['admin_status'] = self.status_to_string(int(value))
        
        # Parse operational status
        for oid, value in snmp_data.items():
            if oid.startswith(self.OID_IF_OPER_STATUS + '.'):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['oper_status'] = self.status_to_string(int(value))
        
        # Parse interface type
        for oid, value in snmp_data.items():
            if oid.startswith(self.OID_IF_TYPE + '.'):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['port_type'] = str(value)
        
        # Parse speed (prefer high-speed if available)
        for oid, value in snmp_data.items():
            if oid.startswith(self.OID_IF_HIGH_SPEED + '.'):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    # High speed is in Mbps, convert to bps
                    ports[if_index]['port_speed'] = int(value) * 1000000
            elif oid.startswith(self.OID_IF_SPEED + '.'):
                if_index = int(oid.split('.')[-1])
                if if_index in ports and ports[if_index]['port_speed'] == 0:
                    ports[if_index]['port_speed'] = int(value)
        
        # Parse MTU
        for oid, value in snmp_data.items():
            if oid.startswith(self.OID_IF_MTU + '.'):
                if_index = int(oid.split('.')[-1])
                if if_index in ports:
                    ports[if_index]['port_mtu'] = int(value)

        # Parse traffic statistics (single pass for efficiency)
        for oid, value in snmp_data.items():
            if_index = None
            try:
                if_index = int(oid.split('.')[-1])
            except (ValueError, IndexError):
                continue
            if if_index not in ports:
                continue
            try:
                if self.OID_IF_HC_IN_OCTETS + '.' in oid:
                    ports[if_index]['in_octets'] = int(value)
                elif self.OID_IF_HC_OUT_OCTETS + '.' in oid:
                    ports[if_index]['out_octets'] = int(value)
                elif self.OID_IF_IN_ERRORS + '.' in oid:
                    ports[if_index]['in_errors'] = int(value)
                elif self.OID_IF_OUT_ERRORS + '.' in oid:
                    ports[if_index]['out_errors'] = int(value)
                elif self.OID_IF_IN_DISCARDS + '.' in oid:
                    ports[if_index]['in_discards'] = int(value)
                elif self.OID_IF_OUT_DISCARDS + '.' in oid:
                    ports[if_index]['out_discards'] = int(value)
            except (ValueError, TypeError):
                pass

        # ── Assign VLAN to each port using _determine_vlan(ifIndex, ...) ────────
        # Exact same pattern as sh_int_status_snmp.py:
        #   for idx in port_indices:
        #       vlan = determine_vlan(idx, untagged_raw, egress_raw, pvid_map, NUM_PORTS)
        # ifIndex IS the bitmap port position for CBS350 (GE1=ifIndex1=bit1).
        for if_index in list(ports.keys()):
            ports[if_index]['vlan_id'] = _determine_vlan(if_index)

        _log.debug(
            f"VLAN assigned: "
            + ", ".join(
                f"port{if_index}→{d['vlan_id']}"
                for if_index, d in sorted(ports.items())
                if d['vlan_id'] is not None
            )
        )

        # Convert to PortInfo objects
        port_list = []
        for port_data in ports.values():
            port_list.append(PortInfo(**port_data))
        
        return port_list
