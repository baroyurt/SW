"""
Cisco Catalyst C9200L OID mapper.
Optimized for Cisco Catalyst 9200L Series Switches (48/24 PoE + 4 SFP uplinks).
Uses the same proven Q-BRIDGE untagged/egress mask VLAN detection as CBS350.
"""

import logging
import re
import binascii
from typing import Dict, List, Any, Optional
from .base import VendorOIDMapper, DeviceInfo, PortInfo

_log = logging.getLogger(__name__)


def _octetstring_to_bytes(value) -> bytes:
    """
    Convert a pysnmp OctetString (or plain bytes) to raw bytes.
    Same implementation as cisco_cbs350.py (proven working).
    """
    if isinstance(value, bytes):
        return value
    if hasattr(value, 'asOctets'):
        try:
            raw = value.asOctets()
            return raw if isinstance(raw, bytes) else bytes(raw)
        except Exception:
            pass
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


class CiscoC9200Mapper(VendorOIDMapper):
    """OID mapper for Cisco Catalyst C9200L switches."""

    # Default port count for C9200L-48P-4G (48 PoE GE + 4 SFP uplinks)
    DEFAULT_PORTS = 52

    # PVID (dot1qPvid) — indexed by ifIndex, works reliably on C9200L
    # Q-BRIDGE bitmap OIDs are NOT used: C9200L's bitmap port-index ≠ ifIndex,
    # causing all ports to appear as VLAN 1 when the bitmap approach is used.
    OID_PVID = '1.3.6.1.2.1.17.7.1.4.5.1.1'  # dot1qPvid

    # Cisco vmVlan fallback (CISCO-VLAN-MEMBERSHIP-MIB)
    OID_CISCO_VLAN = '1.3.6.1.4.1.9.9.68.1.2.2.1.2'  # vmVlan

    # MAC table: Q-BRIDGE (all VLANs) — Cisco IOS-XE returns ifIndex as the port value
    OID_DOT1Q_FDB_PORT   = '1.3.6.1.2.1.17.7.1.2.2.1.2'  # dot1qTpFdbPort
    OID_DOT1Q_FDB_STATUS = '1.3.6.1.2.1.17.7.1.2.2.1.3'  # dot1qTpFdbStatus (3=learned)

    # MAC table: standard Bridge MIB status (3=learned, 4=self/virtual)
    OID_DOT1D_TP_FDB_STATUS = '1.3.6.1.2.1.17.4.3.1.3'  # dot1dTpFdbStatus

    # Port prefixes for Catalyst 9200L
    # GigabitEthernet1/0/1..48 + GigabitEthernet1/1/1..4 (uplinks)
    PHYS_PREFIXES = ('gigabitethernet', 'tengigabitethernet', 'twogigabitethernet')

    def __init__(self):
        super().__init__()
        self.vendor_name = 'cisco'
        self.model_name  = 'c9200'
        # Populated by parse_port_info; used by parse_mac_table to map ifIndex → portNum
        self._if_to_port: Dict[int, int] = {}

    # Compiled regex: matches "GigabitEthernet1/0/N" / "Gi1/0/N" and extracts
    # (slot, subslot, port) groups.  $ anchor rejects sub-interfaces (e.g. .100).
    _PORT_NAME_RE = re.compile(r'[a-z]+(\d+)/(\d+)/(\d+)$')

    @staticmethod
    def _is_physical_port(if_name: str) -> bool:
        """True only for physical data ports (slot 1): GE1/0/N, GE1/1/N, TE1/1/N.
        Explicitly excludes GigabitEthernet0/* (management port), port-0
        sub-module interfaces (internal IOS-XE CPU-facing ports), and
        sub-interfaces (e.g. GigabitEthernet1/0/1.100)."""
        n = if_name.lower()
        # Exclude management port first
        if n.startswith('gigabitethernet0') or n.startswith('te0') or n.startswith('fastethernet0'):
            return False
        for prefix in ('gigabitethernet1/', 'tengigabitethernet1/', 'twogigabitethernet1/'):
            if n.startswith(prefix):
                # Must match exactly slot/subslot/port with a positive port number.
                # Rejects sub-interfaces (GE1/0/1.100) and port-0 entries.
                m = CiscoC9200Mapper._PORT_NAME_RE.match(n)
                if not m or int(m.group(3)) == 0:
                    return False
                return True
        return False

    @staticmethod
    def _to_int(val) -> Optional[int]:
        """Robustly convert a pysnmp value to int.
        Handles Integer32, named integers (e.g. 'up(1)'), and plain ints."""
        if val is None:
            return None
        try:
            return int(val)
        except (TypeError, ValueError):
            pass
        try:
            return int(str(val))
        except (TypeError, ValueError):
            pass
        try:
            # prettyPrint may return 'up(1)' or 'connected(1)' — extract the number
            s = str(val.prettyPrint()).strip()
            if '(' in s and s.endswith(')'):
                return int(s.split('(')[1].rstrip(')'))
            return int(s)
        except Exception:
            pass
        return None

    # ─── Device info ──────────────────────────────────────────────────────────

    def get_device_info_oids(self) -> List[str]:
        return [
            self.OID_SYS_DESCR,
            self.OID_SYS_NAME,
            self.OID_SYS_UPTIME,
        ]

    def parse_device_info(self, snmp_data: Dict[str, Any]) -> DeviceInfo:
        sys_descr  = str(snmp_data.get(self.OID_SYS_DESCR,  'Unknown'))
        sys_name   = str(snmp_data.get(self.OID_SYS_NAME,   'Unknown'))
        sys_uptime = int(snmp_data.get(self.OID_SYS_UPTIME, 0))

        # Parse port count from model string: "C9200L-48P-4G" → 48+4=52
        # _poll_device_info uses get_multiple (SNMP GET), not WALK, so IF_DESCR
        # table cannot be enumerated here; derive count from sysDescr pattern instead.
        port_count = self.DEFAULT_PORTS  # default for C9200L-48P-4G
        m = re.search(r'-(\d+)[PpXx]-(\d+)[Gg]', sys_descr)
        if m:
            port_count = int(m.group(1)) + int(m.group(2))
        else:
            _log.debug('C9200 port count regex did not match sysDescr; using default %d', self.DEFAULT_PORTS)

        vendor = 'Cisco'
        model  = 'C9200L'
        descr_lower = sys_descr.lower()
        for token in ('c9200l', 'c9200', 'catalyst 9200'):
            if token in descr_lower:
                model = token.upper().replace('CATALYST ', 'C')
                break

        return DeviceInfo(
            system_description=sys_descr,
            system_name=sys_name,
            system_uptime=sys_uptime,
            total_ports=port_count,
        )

    # ─── Port info ────────────────────────────────────────────────────────────

    def get_port_info_oids(self) -> List[str]:
        return [
            self.OID_IF_DESCR,
            self.OID_IF_NAME,
            self.OID_IF_ALIAS,
            self.OID_IF_ADMIN_STATUS,
            self.OID_IF_OPER_STATUS,
            self.OID_IF_HIGH_SPEED,
            self.OID_PVID,        # dot1qPvid: VLAN indexed by ifIndex (works correctly)
            self.OID_CISCO_VLAN,  # vmVlan: fallback for access VLAN
        ]

    def get_port_get_oids(self, num_ports: int = 52) -> List[str]:
        return []  # C9200 VLAN covered by OID_PVID walk

    def parse_port_info(self, snmp_data: Dict[str, Any]) -> List[PortInfo]:
        # ── Step 1: build ifIndex → PVID map (VLAN per port) ───────────────
        # dot1qPvid is indexed BY ifIndex — works correctly for C9200L.
        # Q-BRIDGE bitmap OIDs are NOT used: bitmap port-index ≠ ifIndex on C9200L.
        pvid_map: Dict[int, int] = {}
        cisco_vlan_map: Dict[int, int] = {}

        for oid, val in snmp_data.items():
            if self.OID_PVID + '.' in oid:
                try:
                    if_index = int(oid.split('.')[-1])
                    vlan = self._to_int(val)
                    if vlan and vlan > 0:
                        pvid_map[if_index] = vlan
                except Exception:
                    pass
            elif self.OID_CISCO_VLAN + '.' in oid:
                try:
                    if_index = int(oid.split('.')[-1])
                    vlan = self._to_int(val)
                    if vlan and vlan > 0:
                        cisco_vlan_map[if_index] = vlan
                except Exception:
                    pass

        _log.info('C9200 PVID entries: %d, vmVlan entries: %d',
                  len(pvid_map), len(cisco_vlan_map))

        def _determine_vlan(if_index: int) -> Optional[int]:
            """Return access VLAN for this ifIndex using PVID, fallback to vmVlan."""
            pvid = pvid_map.get(if_index)
            if pvid and pvid > 1:
                return pvid
            cisco = cisco_vlan_map.get(if_index)
            if cisco and cisco > 1:
                return cisco
            if if_index in pvid_map:
                return 1
            return None

        # ── Step 2: collect per-port data from ifDescr ─────────────────────
        ports: Dict[int, dict] = {}

        for oid, val in snmp_data.items():
            if self.OID_IF_DESCR + '.' not in oid:
                continue
            try:
                if_index = int(oid.split('.')[-1])
            except ValueError:
                continue
            descr = str(val)
            if self._is_physical_port(descr):
                ports[if_index] = {
                    'port_number': if_index,
                    'port_name':   descr,
                    'port_alias':  '',
                    'admin_status': 'unknown',
                    'oper_status':  'unknown',
                    'port_type':    '',
                    'port_speed':   0,
                    'port_mtu':     0,
                    'mac_address':  None,
                    'vlan_id':      None,
                }

        _log.debug('C9200 physical ports found: %d', len(ports))

        # Fill in remaining OID data
        for oid, val in snmp_data.items():
            try:
                if_index = int(oid.split('.')[-1])
            except (ValueError, IndexError):
                continue
            if if_index not in ports:
                continue

            if self.OID_IF_NAME + '.' in oid:
                name = str(val).strip()
                if name:
                    ports[if_index]['port_name'] = name
            elif self.OID_IF_ALIAS + '.' in oid:
                ports[if_index]['port_alias'] = str(val).strip()
            elif self.OID_IF_ADMIN_STATUS + '.' in oid:
                v = self._to_int(val)
                if v is not None:
                    ports[if_index]['admin_status'] = self.status_to_string(v)
            elif self.OID_IF_OPER_STATUS + '.' in oid:
                v = self._to_int(val)
                if v is not None:
                    ports[if_index]['oper_status'] = self.status_to_string(v)
            elif self.OID_IF_HIGH_SPEED + '.' in oid:
                v = self._to_int(val)
                if v is not None:
                    ports[if_index]['port_speed'] = v * 1_000_000
            # Note: OID_IF_PHYS_ADDRESS is intentionally NOT processed here.
            # ifPhysAddress returns the switch port's own hardware MAC, NOT the
            # connected device's MAC.  mac_address is populated exclusively from
            # the FDB table by _associate_macs_with_ports() so that it always
            # represents the MAC of the device actually connected to the port.

        # Assign VLANs from PVID map
        for if_index, p in ports.items():
            p['vlan_id'] = _determine_vlan(if_index)

        # ── Step 3: renumber ports sequentially 1..N ───────────────────────
        # Sort by interface name components (slot/subslot/port) for deterministic
        # port numbering that matches the physical port order, regardless of ifIndex.
        # e.g. GigabitEthernet1/0/1-48 → 1-48, GigabitEthernet1/1/1-4 → 49-52.
        def _name_sort_key(item):
            _, p = item
            m = CiscoC9200Mapper._PORT_NAME_RE.match(p['port_name'].lower())
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            # Fallback: sort by ifIndex if name format is unexpected
            return (0, 0, item[0])

        # Also build if_index → sequential portNum for MAC table lookup
        self._if_to_port.clear()
        port_list = []
        oper_up = 0
        for seq, (if_idx, p) in enumerate(sorted(ports.items(), key=_name_sort_key), start=1):
            p['port_number'] = seq
            self._if_to_port[if_idx] = seq
            if p.get('oper_status') == 'up':
                oper_up += 1
            port_list.append(PortInfo(**p))

        _log.info('C9200 parse_port_info: %d physical ports, %d UP, %d PVID entries',
                  len(port_list), oper_up, len(pvid_map))
        return port_list

    # ─── MAC table ────────────────────────────────────────────────────────────

    def get_mac_table_oids(self) -> List[str]:
        """Walk only the standard dot1d Bridge FDB and bridge-port→ifIndex map.

        The Q-BRIDGE (dot1q) walk covers all VLANs and can produce an extremely
        large table on C9200L (all VLANs × all MACs).  On some C9200L firmware
        versions this walk stalls the SNMP agent, causing subsequent test_connection()
        calls to fail → "device unreachable" alarms.  The user has confirmed there
        is a known global firmware issue with MAC responses on C9200L ("c9200L
        sürümle ilgili global bir sorun varmış mac vermem gibi").
        The dot1d Bridge MIB (VLAN 1 only) is much smaller and safe."""
        return [
            self.OID_DOT1D_TP_FDB_ADDRESS,    # Bridge MIB MACs (VLAN 1)
            self.OID_DOT1D_TP_FDB_PORT,       # Bridge MIB bridge-port values
            self.OID_DOT1D_TP_FDB_STATUS,     # Bridge MIB status (3=learned, 4=self)
            self.OID_DOT1D_BASE_PORT,         # bridge-port → ifIndex map
        ]

    def parse_mac_table(self, snmp_data: Dict[str, Any]) -> Dict[int, List[str]]:
        """Return only *physical* (learned) MACs mapped to sequential port numbers.

        Uses the standard dot1d Bridge MIB (VLAN 1 only).  Filter: status==3
        (learned); bridge-port must map to a known physical ifIndex (_if_to_port).
        Virtual/self MACs (status 4) are excluded.
        When the status table is absent, all MACs that pass the physical-port
        filter are included (backward-compatible behaviour).

        Note: Q-BRIDGE (dot1qTpFdb) walks are intentionally omitted because
        they can stall the C9200L SNMP agent on certain firmware versions,
        causing subsequent test_connection() calls to fail and generating
        false "device unreachable" alarms.
        """
        if not self._if_to_port:
            # parse_port_info not called yet — best effort via base class
            return super().parse_mac_table(snmp_data)

        # Use sets internally for O(1) deduplication; convert to list at the end.
        result_sets: Dict[int, set] = {}

        # ── dot1d Bridge MIB (VLAN 1) ────────────────────────────────────────
        fdb_status: Dict[str, int] = {}
        for oid, val in snmp_data.items():
            if self.OID_DOT1D_TP_FDB_STATUS + '.' in oid:
                try:
                    mac_parts = oid.split('.')[-6:]
                    mac = ':'.join(f'{int(x):02x}' for x in mac_parts)
                    fdb_status[mac] = self._to_int(val) or 0
                except Exception:
                    pass

        dot1d_has_status = bool(fdb_status)

        bridge_port_to_if: Dict[int, int] = {}
        for oid, val in snmp_data.items():
            if self.OID_DOT1D_BASE_PORT + '.' in oid:
                try:
                    bp = int(oid.split('.')[-1])
                    if_idx = self._to_int(val)
                    if if_idx and if_idx in self._if_to_port:
                        bridge_port_to_if[bp] = if_idx
                except Exception:
                    pass

        for oid, val in snmp_data.items():
            if self.OID_DOT1D_TP_FDB_PORT + '.' in oid:
                try:
                    mac_parts = oid.split('.')[-6:]
                    mac = ':'.join(f'{int(x):02x}' for x in mac_parts)
                    bp = self._to_int(val)
                    status = fdb_status.get(mac)
                    if bp and (not dot1d_has_status or status == 3) and bp in bridge_port_to_if:
                        if_idx = bridge_port_to_if[bp]
                        port_num = self._if_to_port.get(if_idx)
                        if port_num is not None:
                            result_sets.setdefault(port_num, set()).add(mac)
                except Exception:
                    pass

        result: Dict[int, List[str]] = {p: list(macs) for p, macs in result_sets.items()}
        _log.debug('C9200 MAC table (dot1d only): %d ports with MACs', len(result))
        return result
