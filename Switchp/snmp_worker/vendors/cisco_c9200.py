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

# How many poll cycles between full VLAN rediscovery scans.
# In normal operation we only scan the VLANs that returned MACs in the previous
# cycle; every _VLAN_REDISCOVERY_INTERVAL cycles we also scan ALL ALLOWED_VLANS
# so newly configured VLANs are picked up automatically.
_VLAN_REDISCOVERY_INTERVAL = 10


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

    # Whitelist of data VLANs to scan — same set as C9300L.py ALLOWED_VLANS.
    # On C9200L IOS-XE, dot1qPvid typically returns 0 or 1 for all access
    # ports so PVID-based discovery misses data VLANs like 70.  Always scan
    # this fixed set instead of relying on discovered active_vlans.
    # Includes WiFi-adjacent VLANs (30 GUEST, 40 VIP) so physical devices on
    # those VLANs (when VLAN 70 / AP is absent) are also captured.
    # Also includes 150 (JACKPOT) and 1500 (DRGT) for multi-MAC Hub detection.
    ALLOWED_VLANS: frozenset = frozenset({30, 40, 50, 70, 130, 140, 150, 254, 1500})

    # Native VLAN for AP trunk ports.  A port that has MAC entries in this VLAN
    # AND in WiFi companion VLANs simultaneously is treated as an AP uplink:
    # only MACs learned in AP_VLAN (the physical/wired side) are tracked,
    # discarding WiFi client MACs from roaming phones on companion VLANs.
    AP_VLAN: int = 70

    # WiFi companion VLANs: only these VLANs, when found alongside AP_VLAN on
    # the same port, indicate an AP trunk port.  Non-WiFi VLANs (e.g. 150
    # JACKPOT, 1500 DRGT) must NOT trigger AP trunk detection even if they
    # co-exist with VLAN 70 on the same port.
    # Includes all WiFi SSID VLANs: 30 (GUEST), 40 (VIP), 50 (DEVICE),
    # 130 (TV), 140 (SANTRAL), 254 (SERVER).
    AP_COMPANION_VLANS: frozenset = frozenset({30, 40, 50, 130, 140, 254})

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
        # Populated by parse_port_info; used by collect_mac_with_vlan_contexts to
        # filter MACs so each port only shows MACs from its own VLAN.
        self._port_vlan_map: Dict[int, int] = {}
        # ── VLAN context caching ────────────────────────────────────────────
        # After the first successful MAC context walk, remember which VLANs
        # actually returned ≥1 MAC entry.  Subsequent polls only scan those
        # VLANs, saving (N_total - N_active) × 4 SNMP walks per cycle.
        # Every _VLAN_REDISCOVERY_INTERVAL cycles we fall back to scanning all
        # ALLOWED_VLANS so newly configured VLANs are always picked up.
        self._cached_active_vlans: Optional[frozenset[int]] = None  # VLANs with data
        self._vlan_cache_poll_count: int = 0  # cycles since last full rescan

    # Environmental monitoring OIDs (CISCO-ENVMON-MIB)
    OID_ENV_TEMP_VALUE      = '1.3.6.1.4.1.9.9.13.1.3.1.3.1'  # ciscoEnvMonTemperatureStatusValue.1
    OID_ENV_FAN_STATE       = '1.3.6.1.4.1.9.9.13.1.4.1.3.1'  # ciscoEnvMonFanState.1
    # Base OIDs for table walks — sensor index is not always .1 on IOS-XE devices
    OID_ENV_TEMP_VALUE_BASE = '1.3.6.1.4.1.9.9.13.1.3.1.3'    # ciscoEnvMonTemperatureStatusValue table
    OID_ENV_FAN_STATE_BASE  = '1.3.6.1.4.1.9.9.13.1.4.1.3'    # ciscoEnvMonFanState table

    # PoE MIB (pethMainPseTable, module index 1) — switch-level budget
    OID_POE_NOMINAL  = '1.3.6.1.2.1.105.1.3.1.2.1'  # pethMainPseNominalPower.1
    OID_POE_CONSUMED = '1.3.6.1.2.1.105.1.3.1.4.1'  # pethMainPseConsumptionPower.1

    # PoE MIB (pethPsePortTable, RFC 3621) — per-port PoE status
    # Index: {GroupIndex}.{PortIndex}  (GroupIndex always 1 for single-module C9200L)
    OID_PETH_PORT_DETECT = '1.3.6.1.2.1.105.1.1.1.6'   # pethPsePortDetectStatus (3=deliveringPower)
    OID_PETH_PORT_CLASS  = '1.3.6.1.2.1.105.1.1.1.7'   # pethPsePortPowerClassifications (Cisco: 0=class0…4=class4)
    OID_PETH_PORT_MW     = '1.3.6.1.2.1.105.1.1.1.10'  # pethPsePortPowerConsumption — milliwatts per RFC 3621

    # CPU load — Cisco OLD-CISCO-CPU-MIB scalar GETs (IOS / IOS-XE)
    OID_CPU_1MIN = '1.3.6.1.4.1.9.2.1.57.0'  # lcpu1MinAvg

    # Memory — ciscoMemoryPoolMIB, Processor pool (index 1)
    OID_MEM_USED = '1.3.6.1.4.1.9.9.48.1.1.1.5.1'  # ciscoMemoryPoolUsed.1
    OID_MEM_FREE = '1.3.6.1.4.1.9.9.48.1.1.1.6.1'  # ciscoMemoryPoolFree.1

    # ciscoEnvMonFanState values: 1=normal,2=warning,3=critical,4=shutdown,5=notPresent,6=notFunctioning
    _FAN_STATE_MAP = {1: 'OK', 2: 'WARNING', 3: 'CRITICAL', 4: 'CRITICAL', 5: 'N/A', 6: 'N/A'}

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
            # Environmental + PoE scalar GETs (index .1 — may not exist on all IOS-XE)
            # get_device_info_walk_oids() additionally walks the full tables so that
            # sensors at indices other than .1 are also discovered.
            self.OID_ENV_TEMP_VALUE,
            self.OID_ENV_FAN_STATE,
            self.OID_POE_NOMINAL,
            self.OID_POE_CONSUMED,
            # CPU load (1-minute average)
            self.OID_CPU_1MIN,
            # Memory pool (Processor pool)
            self.OID_MEM_USED,
            self.OID_MEM_FREE,
        ]

    def get_device_info_walk_oids(self) -> List[str]:
        """Walk the full CISCO-ENVMON temperature and fan tables.

        C9300L (and some C9200 models) may expose temperature/fan sensors at
        table indices other than .1, causing the scalar GET in
        get_device_info_oids() to return noSuchInstance.  Walking the parent
        column OIDs guarantees discovery regardless of the sensor row index.
        """
        return [
            self.OID_ENV_TEMP_VALUE_BASE,
            self.OID_ENV_FAN_STATE_BASE,
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
        model  = 'Cisco Catalyst'
        descr_lower = sys_descr.lower()
        for token in ('c9300l', 'catalyst 9300', 'c9300', 'c9200l', 'catalyst 9200', 'c9200'):
            if token in descr_lower:
                model = token.upper().replace('CATALYST ', 'C')
                break

        # ── Environmental: temperature (index-agnostic scan) ────────────────
        # Scans both the scalar OID (index .1) and all walk results from the
        # full ciscoEnvMonTemperatureStatusValue table.  C9300L sensors are
        # sometimes only present at index .4 or higher, so the scalar GET at
        # .1 returns noSuchInstance while the table walk finds the value.
        temperature_c = None
        try:
            for key, tv in snmp_data.items():
                if key == self.OID_ENV_TEMP_VALUE or key.startswith(self.OID_ENV_TEMP_VALUE_BASE + '.'):
                    try:
                        t = int(tv)
                        if 0 < t < 200:
                            temperature_c = float(t)
                            break
                    except Exception:
                        continue
        except Exception:
            pass

        # ── Environmental: fan state (index-agnostic scan, worst state wins) ─
        fan_status = None
        _fan_worst = 0
        try:
            for key, fv in snmp_data.items():
                if key == self.OID_ENV_FAN_STATE or key.startswith(self.OID_ENV_FAN_STATE_BASE + '.'):
                    try:
                        iv = int(fv)
                        if 1 <= iv <= 4 and iv > _fan_worst:
                            _fan_worst = iv
                    except Exception:
                        pass
            if _fan_worst > 0:
                fan_status = self._FAN_STATE_MAP.get(_fan_worst, 'N/A')
        except Exception:
            pass

        # ── PoE budget ──────────────────────────────────────────────────────
        poe_nominal = None
        poe_consumed = None
        try:
            nom = snmp_data.get(self.OID_POE_NOMINAL)
            con = snmp_data.get(self.OID_POE_CONSUMED)
            if nom is not None:
                n = int(nom)
                if n > 0:
                    poe_nominal  = n
                    poe_consumed = int(con) if con is not None else 0
        except (TypeError, ValueError):
            pass

        return DeviceInfo(
            system_description=sys_descr,
            system_name=sys_name,
            system_uptime=sys_uptime,
            total_ports=port_count,
            fan_status=fan_status,
            temperature_c=temperature_c,
            poe_nominal_w=poe_nominal,
            poe_consumed_w=poe_consumed,
            cpu_1min=self._parse_cpu_1min(snmp_data),
            memory_usage=self._parse_memory_usage(snmp_data),
        )

    def _parse_cpu_1min(self, snmp_data: Dict[str, Any]) -> Optional[int]:
        """Parse 1-minute CPU average from SNMP data."""
        try:
            v = snmp_data.get(self.OID_CPU_1MIN)
            if v is not None:
                cpu = int(v)
                if 0 <= cpu <= 100:
                    return cpu
        except (TypeError, ValueError):
            pass
        return None

    def _parse_memory_usage(self, snmp_data: Dict[str, Any]) -> Optional[float]:
        """Parse memory utilisation % from ciscoMemoryPoolMIB (Processor pool)."""
        try:
            used = snmp_data.get(self.OID_MEM_USED)
            free = snmp_data.get(self.OID_MEM_FREE)
            if used is not None and free is not None:
                u = int(used)
                f = int(free)
                total = u + f
                if total > 0:
                    return round(u / total * 100, 1)
        except (TypeError, ValueError):
            pass
        return None

    # ─── Port info ────────────────────────────────────────────────────────────

    def get_port_info_oids(self) -> List[str]:
        """Walk two parent MIB tables plus two vendor-specific VLAN OIDs.

        Replaces 14 individual column-level GETBULK walks with 4 walks using
        parent-table prefixes.  Each fresh SnmpEngine incurs SNMPv3 key
        derivation + engine-discovery (~3 s overhead per call), so reducing
        from 14 to 4 sessions saves ~30 s per device poll cycle.

        Parent prefixes used:
          1.3.6.1.2.1.2.2.1   – ifTable (ifDescr, ifAdminStatus, ifOperStatus,
                                  ifInErrors, ifOutErrors, ifInDiscards,
                                  ifOutDiscards, …)
          1.3.6.1.2.1.31.1.1.1 – ifXTable (ifName, ifAlias, ifHighSpeed,
                                  ifHCInOctets, ifHCOutOctets, …)
        The PVID and Cisco vmVlan OIDs are in distinct MIB subtrees and must
        remain as separate walks.
        """
        return [
            self.OID_IF_TABLE,              # entire ifTable  (columns .2 – .22)
            '1.3.6.1.2.1.31.1.1.1',         # entire ifXTable (columns .1 – .18)
            self.OID_PVID,                  # dot1qPvid – separate subtree
            self.OID_CISCO_VLAN,            # vmVlan – Cisco enterprise OID
            '1.3.6.1.2.1.105.1.1.1',         # pethPsePortTable (per-port PoE, RFC 3621)
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
            elif self.OID_IF_HC_IN_OCTETS + '.' in oid:
                v = self._to_int(val)
                if v is not None:
                    ports[if_index]['in_octets'] = v
            elif self.OID_IF_HC_OUT_OCTETS + '.' in oid:
                v = self._to_int(val)
                if v is not None:
                    ports[if_index]['out_octets'] = v
            elif self.OID_IF_IN_ERRORS + '.' in oid:
                v = self._to_int(val)
                if v is not None:
                    ports[if_index]['in_errors'] = v
            elif self.OID_IF_OUT_ERRORS + '.' in oid:
                v = self._to_int(val)
                if v is not None:
                    ports[if_index]['out_errors'] = v
            elif self.OID_IF_IN_DISCARDS + '.' in oid:
                v = self._to_int(val)
                if v is not None:
                    ports[if_index]['in_discards'] = v
            elif self.OID_IF_OUT_DISCARDS + '.' in oid:
                v = self._to_int(val)
                if v is not None:
                    ports[if_index]['out_discards'] = v
            # Note: OID_IF_PHYS_ADDRESS is intentionally NOT processed here.
            # ifPhysAddress returns the switch port's own hardware MAC, NOT the
            # connected device's MAC.  mac_address is populated exclusively from
            # the FDB table by _associate_macs_with_ports() so that it always
            # represents the MAC of the device actually connected to the port.

        # Assign VLANs from PVID map
        for if_index, p in ports.items():
            p['vlan_id'] = _determine_vlan(if_index)

        # ── Per-port PoE (pethPsePortTable, RFC 3621) ───────────────────────
        # Index format: {GroupIndex}.{PortIndex}  (GroupIndex=1 for C9200L)
        # On IOS-XE, PortIndex == the sequential port number (1..48 for C9200L-48P).
        # OID_PETH_PORT_MW (.10) returns milliwatts per RFC 3621 UNITS definition.
        poe_detect_map: Dict[int, int] = {}   # port_idx → detect status
        poe_class_map:  Dict[int, int] = {}   # port_idx → class enum
        poe_mw_map:     Dict[int, int] = {}   # port_idx → milliwatts (RFC 3621)

        for oid, val in snmp_data.items():
            for col_oid, target_map in (
                (self.OID_PETH_PORT_DETECT, poe_detect_map),
                (self.OID_PETH_PORT_CLASS,  poe_class_map),
                (self.OID_PETH_PORT_MW,     poe_mw_map),
            ):
                if oid.startswith(col_oid + '.'):
                    suffix = oid[len(col_oid) + 1:]
                    parts = suffix.split('.')
                    if len(parts) >= 2:
                        try:
                            group_idx = int(parts[0])
                            port_idx  = int(parts[1])
                            if group_idx == 1:
                                v = self._to_int(val)
                                if v is not None:
                                    target_map[port_idx] = v
                        except (ValueError, IndexError):
                            pass

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
        self._port_vlan_map.clear()
        port_list = []
        oper_up = 0
        for seq, (if_idx, p) in enumerate(sorted(ports.items(), key=_name_sort_key), start=1):
            p['port_number'] = seq
            self._if_to_port[if_idx] = seq
            vlan = p.get('vlan_id')
            # VLAN 1 is the default/unassigned VLAN; skip it so trunk ports
            # and unconfigured interfaces are not mistakenly filtered.
            if vlan and vlan > 1:
                self._port_vlan_map[seq] = vlan
            if p.get('oper_status') == 'up':
                oper_up += 1
            # Attach per-port PoE using sequential port number (seq) as PortIndex.
            # IOS-XE pethPsePortTable PortIndex == sequential port order.
            detect_val = poe_detect_map.get(seq)
            if detect_val is not None:
                p['poe_detecting'] = (detect_val == 3)  # 3 = deliveringPower
                mw = poe_mw_map.get(seq, 0)
                p['poe_power_mw']  = mw                  # RFC 3621: value is already in milliwatts
                p['poe_class']     = poe_class_map.get(seq)
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

    def collect_mac_with_vlan_contexts(
        self,
        snmp_client: Any,
        active_vlans: Optional[List[int]] = None,
    ) -> Dict[int, List[str]]:
        """Collect MAC addresses using per-VLAN SNMPv3 contexts.

        Cisco IOS-XE (C9200L / C9300L) puts the Bridge FDB behind a per-VLAN
        SNMP context (``vlan-<id>``).  A plain walk with the empty context
        returns nothing.

        When ``active_vlans`` is not provided (or empty), ALLOWED_VLANS
        {50, 70, 130, 140, 254} is used.  On C9200L IOS-XE, dot1qPvid
        returns 0 / 1 for all access ports so PVID-based discovery misses
        data VLANs like 70; the fixed whitelist guarantees they are scanned.

        Strategy per VLAN:
          1. dot1qTpFdbPort (preferred) — returns ifIndex directly, no
             bridge-port mapping required.  Used when the walk returns data.
          2. dot1dTpFdbPort (fallback) — requires bridge-port → ifIndex map
             from dot1dBasePortIfIndex.

        Args:
            snmp_client: SNMPClient instance with get_bulk_with_context().
            active_vlans: VLANs to query.  If None / empty, defaults to
                          sorted(ALLOWED_VLANS).

        Returns:
            Dict mapping sequential port_number → list of MAC strings.
        """
        if not self._if_to_port:
            _log.warning('collect_mac_with_vlan_contexts called before parse_port_info')
            return {}

        # ── VLAN list selection (with caching) ──────────────────────────────
        # On C9200L IOS-XE, dot1qPvid returns 0/1 for all access ports so
        # discovery-based VLAN lists miss data VLANs like 70.  We maintain a
        # per-device cache of VLANs that actually returned MACs last cycle so
        # that subsequent polls only walk those VLANs (typically 2–4 out of 9),
        # reducing per-device poll time by ~60-70%.
        # Every _VLAN_REDISCOVERY_INTERVAL cycles we scan ALL ALLOWED_VLANS so
        # newly configured VLANs are always discovered.
        self._vlan_cache_poll_count += 1
        is_full_scan = (
            not self._cached_active_vlans
            or self._vlan_cache_poll_count % _VLAN_REDISCOVERY_INTERVAL == 0
        )
        if is_full_scan:
            active_vlans = sorted(self.ALLOWED_VLANS)
            _log.debug('VLAN full rescan (cycle %d): %s', self._vlan_cache_poll_count, active_vlans)
        else:
            active_vlans = sorted(self._cached_active_vlans)
            _log.debug('VLAN cached scan (cycle %d): %s', self._vlan_cache_poll_count, active_vlans)

        # Internal: store (mac, vlan_id) tuples per port for VLAN-based filtering.
        result_sets: Dict[int, set] = {}
        total_macs = 0

        for vlan_id in active_vlans:
            ctx = f"vlan-{vlan_id}"
            vlan_count = 0

            # ── 1. dot1qTpFdbPort (ifIndex direct) ──────────────────────────
            q_entries = list(snmp_client.get_bulk_with_context(self.OID_DOT1Q_FDB_PORT, ctx))
            if q_entries:
                for oid, val in q_entries:
                    if self.OID_DOT1Q_FDB_PORT + '.' not in oid:
                        continue
                    try:
                        mac_parts = oid.split('.')[-6:]
                        mac = ':'.join(f'{int(x):02x}' for x in mac_parts)
                        if_idx = self._to_int(val)
                        if if_idx and if_idx in self._if_to_port:
                            port_num = self._if_to_port[if_idx]
                            result_sets.setdefault(port_num, set()).add((mac, vlan_id))
                            vlan_count += 1
                    except Exception:
                        pass

                if vlan_count:
                    _log.debug('VLAN %d context (dot1qTpFdb): %d MACs', vlan_id, vlan_count)
                    total_macs += vlan_count
                continue  # dot1q succeeded — skip dot1d fallback

            # ── 2. dot1dTpFdbPort fallback (bridge-port mapping needed) ─────
            bp_to_if: Dict[int, int] = {}
            for oid, val in snmp_client.get_bulk_with_context(self.OID_DOT1D_BASE_PORT, ctx):
                if self.OID_DOT1D_BASE_PORT + '.' not in oid:
                    continue
                try:
                    bp = int(oid.split('.')[-1])
                    if_idx = self._to_int(val)
                    if if_idx and if_idx in self._if_to_port:
                        bp_to_if[bp] = if_idx
                except Exception:
                    pass

            # dot1dTpFdbStatus (filter: status==3 learned)
            fdb_status: Dict[str, int] = {}
            for oid, val in snmp_client.get_bulk_with_context(self.OID_DOT1D_TP_FDB_STATUS, ctx):
                if self.OID_DOT1D_TP_FDB_STATUS + '.' not in oid:
                    continue
                try:
                    mac_parts = oid.split('.')[-6:]
                    mac = ':'.join(f'{int(x):02x}' for x in mac_parts)
                    fdb_status[mac] = self._to_int(val) or 0
                except Exception:
                    pass

            has_status = bool(fdb_status)

            for oid, val in snmp_client.get_bulk_with_context(self.OID_DOT1D_TP_FDB_PORT, ctx):
                if self.OID_DOT1D_TP_FDB_PORT + '.' not in oid:
                    continue
                try:
                    mac_parts = oid.split('.')[-6:]
                    mac = ':'.join(f'{int(x):02x}' for x in mac_parts)
                    bp = self._to_int(val)
                    if not bp:
                        continue
                    status = fdb_status.get(mac)
                    if has_status and status != 3:
                        continue
                    # Try bridge-port mapping first
                    if_idx = bp_to_if.get(bp)
                    # Fallback: on Cisco IOS-XE, FDB port value == ifIndex directly
                    if if_idx is None and bp in self._if_to_port:
                        if_idx = bp
                    if if_idx is not None:
                        port_num = self._if_to_port.get(if_idx)
                        if port_num is not None:
                            result_sets.setdefault(port_num, set()).add((mac, vlan_id))
                            vlan_count += 1
                except Exception:
                    pass

            if vlan_count:
                _log.debug('VLAN %d context (dot1dTpFdb): %d MACs', vlan_id, vlan_count)
                total_macs += vlan_count

        # ── Update _port_vlan_map with VLANs discovered from context walks ──────
        # On C9200L IOS-XE, dot1qPvid / vmVlan return 0 or 1 for all access ports,
        # so the parse_port_info PVID-based VLAN assignments are wrong.
        # The per-VLAN context MAC walk is the only reliable VLAN source:
        # if a port's FDB entries are in the "vlan-70" context, that port is VLAN 70.
        # Choose the VLAN whose context contributed the most MAC entries per port.
        port_vlan_votes: Dict[int, Dict[int, int]] = {}
        for port_num, mac_vlan_set in result_sets.items():
            for _mac, vlan in mac_vlan_set:
                port_vlan_votes.setdefault(port_num, {}).setdefault(vlan, 0)
                port_vlan_votes[port_num][vlan] += 1
        for port_num, vlan_counts in port_vlan_votes.items():
            if not vlan_counts:
                continue
            vlans_on_port = set(vlan_counts.keys())
            # AP trunk detection: a port with MACs in AP_VLAN (70) AND in other
            # VLANs simultaneously is an AP uplink carrying both the physical
            # device (VLAN 70) and WiFi clients (other VLANs).  Force its map
            # entry to AP_VLAN so the final filtering step retains only the
            # physical-VLAN MACs and discards WiFi client MACs from roaming
            # phones.  This prevents false "MAC moved" alarms when phones roam.
            if self.AP_VLAN in vlans_on_port and (vlans_on_port & self.AP_COMPANION_VLANS):  # trunk: AP + WiFi VLANs
                self._port_vlan_map[port_num] = self.AP_VLAN
                _log.debug('C9200 AP trunk detected: port %d → VLAN %d (AP native VLAN)',
                           port_num, self.AP_VLAN)
                continue
            best_vlan = max(vlan_counts, key=vlan_counts.get)
            if best_vlan > 1:
                self._port_vlan_map[port_num] = best_vlan
                _log.debug('C9200 VLAN discovery: port %d → VLAN %d (MAC context walk)',
                           port_num, best_vlan)

        # Build final result, filtering each port to only its own VLAN's MACs.
        # This prevents AP-bridged MACs from foreign VLANs appearing on the port.
        # Ports without a known VLAN (port_vlan_map miss = VLAN 1 / trunk /
        # unconfigured) bypass filtering and show all collected MACs.
        result: Dict[int, List[str]] = {}
        for port_num, mac_vlan_set in result_sets.items():
            port_vlan = self._port_vlan_map.get(port_num)
            if port_vlan:
                # Access port: only keep MACs learned in the port's own VLAN.
                filtered = sorted({mac for mac, vlan in mac_vlan_set if vlan == port_vlan})
            else:
                # VLAN 1 / trunk / unconfigured: show all MACs without filtering.
                filtered = sorted({mac for mac, vlan in mac_vlan_set})
            if filtered:
                result[port_num] = filtered
        _log.info('C9200/C9300 VLAN-context MAC table: %d ports with MACs (%d total)',
                  len(result), total_macs)

        # ── Update VLAN cache ─────────────────────────────────────────────────
        # After a full scan, record which VLANs returned ≥1 MAC so next cycle
        # only those VLANs are walked (saves (N_allowed - N_active) × 4 SNMP
        # walks and dramatically reduces per-device Phase 1 poll time).
        if is_full_scan:
            found_vlans = frozenset(
                vlan for _, mac_vlan_set in result_sets.items() for _, vlan in mac_vlan_set
            )
            if found_vlans:
                self._cached_active_vlans = found_vlans
                _log.info('VLAN cache updated: %d/%d active VLANs %s',
                          len(found_vlans), len(self.ALLOWED_VLANS), sorted(found_vlans))
            else:
                # No MACs found at all — reset cache to force full scan next cycle
                self._cached_active_vlans = None

        return result
