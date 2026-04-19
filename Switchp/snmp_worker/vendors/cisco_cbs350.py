"""
Cisco CBS350 OID mapper.
Optimized for Cisco CBS350 Access Switch (Small Business).
"""

import logging
import binascii
import re
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

    # Q-BRIDGE VLAN-aware FDB: index is <fdb_id>.<mac_6_octets> where fdb_id == vlan_id
    OID_DOT1Q_FDB_PORT = '1.3.6.1.2.1.17.7.1.2.2.1.2'   # dot1qTpFdbPort

    def __init__(self):
        """Initialize Cisco CBS350 mapper."""
        super().__init__()
        self.vendor_name = "cisco"
        self.model_name = "cbs350"
        # Maps ifIndex -> port_number (CBS350: ifIndex == port_number, but
        # the map is kept explicit for consistency with C9200/C9300).
        self._if_to_port: Dict[int, int] = {}
        # Maps port_number -> vlan_id (updated by parse_mac_table with AP trunk detection)
        self._port_vlan_map: Dict[int, int] = {}
        # Per-unit physical port count derived from the model string in
        # parse_device_info().  Used by parse_port_info() to cap the result to
        # the first N ports (unit 1) and discard phantom interfaces from
        # unconfigured stack members (units 2-4).
        self._expected_port_count: int = 0
        # PoE-capable port count (access/copper ports only, NOT fiber/SFP+ uplinks).
        # e.g. CBS350-48FP-4X: _poe_port_count=48, _expected_port_count=52.
        # Used by get_port_get_oids() to limit pethPsePortTable GETs to real
        # PoE ports and avoid issuing GETs for SFP+ uplinks that always return
        # noSuchInstance and waste SNMP agent capacity.
        self._poe_port_count: int = 0
    
    # Environmental monitoring OIDs (CISCO-ENVMON-MIB, index .1)
    OID_ENV_TEMP_VALUE = '1.3.6.1.4.1.9.9.13.1.3.1.3.1'  # ciscoEnvMonTemperatureStatusValue.1
    OID_ENV_TEMP_STATE = '1.3.6.1.4.1.9.9.13.1.3.1.6.1'  # ciscoEnvMonTemperatureState.1
    OID_ENV_FAN_STATE  = '1.3.6.1.4.1.9.9.13.1.4.1.3.1'  # ciscoEnvMonFanState.1
    # Parent table column OIDs (no instance suffix) used for table walks.
    # CBS350 sensors are not always at index .1; walking the parent column
    # discovers sensors at any index (see get_device_info_walk_oids()).
    OID_ENV_TEMP_VALUE_BASE = '1.3.6.1.4.1.9.9.13.1.3.1.3'  # ciscoEnvMonTemperatureStatusValue table
    OID_ENV_FAN_STATE_BASE  = '1.3.6.1.4.1.9.9.13.1.4.1.3'  # ciscoEnvMonFanState table

    # CISCOSB-HWENVIROMENT MIB (.101.83) — primary path for CBS350 temperature and fan.
    # Confirmed working by LibreNMS ciscosb.yaml (resources/definitions/os_discovery/ciscosb.yaml).
    #
    # rlEnvFanDataTable (.83.5.1.1) — per-fan sensor data:
    #   .2 = rlEnvFanDataTemp   (INTEGER, degrees Celsius — direct, no conversion needed)
    #   .3 = rlEnvFanDataSpeed  (INTEGER, RPM)
    #
    # rlEnvMonFanTable (.83.1.1.1) — per-fan state:
    #   .3 = rlEnvMonFanState   (1=normal, 2=warning, 3=critical, 4=shutdown,
    #                            5=notPresent, 6=notFunctioning)
    OID_RL_HW_FAN_DATA_TEMP_BASE = '1.3.6.1.4.1.9.6.1.101.83.5.1.1.2'  # rlEnvFanDataTemp
    OID_RL_HW_FAN_STATE_BASE     = '1.3.6.1.4.1.9.6.1.101.83.1.1.1.3'  # rlEnvMonFanState

    # CISCOSB-ENVMON-MIB legacy table (.101.13) — secondary fallback.
    # rlEnvMonTable actual column layout:
    #   .2 = rlEnvMonDescr        (DisplayString, e.g. "FAN 1", "TEMP 1")
    #   .3 = rlEnvMonCurrentState (1=normal … 6=notFunctioning)
    # Column .4 does not exist; this table provides no numeric temperature value.
    OID_RL_ENV_DESCR_BASE      = '1.3.6.1.4.1.9.6.1.101.13.1.1.2'  # rlEnvMonDescr (string)
    OID_RL_ENV_STATE_BASE      = '1.3.6.1.4.1.9.6.1.101.13.1.1.3'  # rlEnvMonCurrentState (1-6)
    # Aliases kept for parse_device_info() compatibility.
    OID_RL_ENV_TYPE_BASE       = OID_RL_ENV_DESCR_BASE
    OID_RL_ENV_FAN_STATE_BASE  = OID_RL_ENV_STATE_BASE
    OID_RL_ENV_TEMP_VALUE_BASE = '1.3.6.1.4.1.9.6.1.101.13.1.1.4'  # non-existent; kept for compat

    # ENTITY-SENSOR-MIB (RFC 3433) -- tertiary fallback for CBS350.
    # CBS350 exposes temperature (and optionally fan) sensors here when the
    # CISCO-ENVMON-MIB and CISCOSB-ENVMON-MIB paths are absent.
    OID_ENT_SENSOR_TYPE  = '1.3.6.1.2.1.99.1.1.1.1'  # entPhySensorType  (8=celsius, 10=rpm, 12=truthvalue)
    OID_ENT_SENSOR_SCALE = '1.3.6.1.2.1.99.1.1.1.2'  # entPhySensorScale (8=milli, 9=units)
    OID_ENT_SENSOR_VALUE = '1.3.6.1.2.1.99.1.1.1.4'  # entPhySensorValue (actual reading)

    # ENTITY-MIB (RFC 2737) — used to find sensor indices by description.
    # entPhysicalDescr (.47.1.1.1.1.2.INDEX) returns a string like
    # "Switch Temperature Sensor" or "Fan Tray 1".
    # Walk this table, filter by keyword ("temp"/"fan"), then use the
    # matching INDEX with OID_ENT_SENSOR_VALUE to get the reading.
    OID_ENT_PHYS_DESCR   = '1.3.6.1.2.1.47.1.1.1.1.2'  # entPhysicalDescr (string)

    # PoE MIB (pethMainPseTable, module index 1) — switch-level budget
    OID_POE_NOMINAL   = '1.3.6.1.2.1.105.1.3.1.2.1'  # pethMainPseNominalPower.1
    OID_POE_CONSUMED  = '1.3.6.1.2.1.105.1.3.1.4.1'  # pethMainPseConsumptionPower.1
    OID_POE_NOMINAL_BASE  = '1.3.6.1.2.1.105.1.3.1.2'  # pethMainPseNominalPower table
    OID_POE_CONSUMED_BASE = '1.3.6.1.2.1.105.1.3.1.4'  # pethMainPseConsumptionPower table

    # PoE MIB (pethPsePortTable, RFC 3621) — per-port PoE status
    # Index: {GroupIndex}.{PortIndex}  (GroupIndex always 1 for CBS350)
    OID_PETH_PORT_DETECT = '1.3.6.1.2.1.105.1.1.1.6'   # pethPsePortDetectStatus (3=deliveringPower)
    OID_PETH_PORT_CLASS  = '1.3.6.1.2.1.105.1.1.1.7'   # pethPsePortPowerClassifications (RFC: 1=class0…5=class4)
    OID_PETH_PORT_MW     = '1.3.6.1.2.1.105.1.1.1.10'  # pethPsePortPowerConsumption — always 0 on CBS350 (not implemented)

    # CISCO-SB-POE-MIB — per-port real-time consumption (milliwatts)
    # pethPsePortPowerConsumption (RFC 3621 OID .10) is NOT implemented on CBS350 and
    # always returns 0.  The correct OID is rlPoePsePortConsumptionPower from the
    # CISCOSB proprietary MIB (CISCO-SB-POE-MIB), column 15 of rlPoePsePortTable:
    #   rlPoePsePortConsumptionPower = 1.3.6.1.4.1.9.6.1.108.1.1.15
    # Indexed by {GroupIndex}.{PortIndex} (e.g. .1.14 for group 1, port 14).
    OID_RL_POE_PORT_MW = '1.3.6.1.4.1.9.6.1.108.1.1.15'  # rlPoePsePortConsumptionPower (milliwatts)

    # CPU — CISCOSB-rndMng MIB (rndMng tree: 1.3.6.1.4.1.9.6.1.101.1)
    # Confirmed correct OIDs per CISCOSB-RNDMNG MIB, Centreon and LibreNMS references:
    #   rlCpuUtilDuringLastSecond  = .1.7.0
    #   rlCpuUtilDuringLastMinute  = .1.8.0   ← used here
    #   rlCpuUtilDuringLast5Mins   = .1.9.0
    OID_CPU_1MIN = '1.3.6.1.4.1.9.6.1.101.1.8.0'  # rlCpuUtilDuringLastMinute (%)

    # Memory — CISCOSB-rndMng MIB scalar GETs (preferred for CBS350)
    # rlFreeMemory / rlTotalMemory are scalar GET instances (.0) in the
    # CISCOSB-RNDMNG MIB.  Formula: used = total - free; usage% = used/total*100.
    OID_RL_FREE_MEMORY  = '1.3.6.1.4.1.9.6.1.101.1.100.0'  # rlFreeMemory  (bytes)
    OID_RL_TOTAL_MEMORY = '1.3.6.1.4.1.9.6.1.101.1.101.0'  # rlTotalMemory (bytes)

    # Memory — HOST-RESOURCES-MIB hrStorageTable (RFC 2790, widely supported)
    # CBS350 does not expose memory via CISCOSB-specific OIDs; hrStorageTable
    # is the standard fallback.  Walked in get_device_info_walk_oids() so that
    # _parse_memory_hr() can find the RAM entry regardless of row index.
    OID_HR_STORAGE_TYPE  = '1.3.6.1.2.1.25.2.3.1.2'   # hrStorageType  (table column)
    OID_HR_STORAGE_UNITS = '1.3.6.1.2.1.25.2.3.1.4'   # hrStorageAllocationUnits (bytes)
    OID_HR_STORAGE_SIZE  = '1.3.6.1.2.1.25.2.3.1.5'   # hrStorageSize  (units)
    OID_HR_STORAGE_USED  = '1.3.6.1.2.1.25.2.3.1.6'   # hrStorageUsed  (units)
    # OID value that identifies a RAM storage entry
    OID_HR_STORAGE_RAM   = '1.3.6.1.2.1.25.2.1.2'     # hrStorageRam type OID

    # ciscoEnvMonFanState values: 1=normal,2=warning,3=critical,4=shutdown,5=notPresent,6=notFunctioning
    _FAN_STATE_MAP = {1: 'OK', 2: 'WARNING', 3: 'CRITICAL', 4: 'CRITICAL', 5: 'N/A', 6: 'N/A'}

    def get_device_info_oids(self) -> List[str]:
        """Get OIDs for device information."""
        return [
            self.OID_SYS_DESCR,
            self.OID_SYS_NAME,
            self.OID_SYS_UPTIME,
            self.OID_IF_NUMBER,
            self.OID_SYS_CONTACT,
            self.OID_SYS_LOCATION,
            # Environmental scalar GETs (index .1 — may succeed on some firmware).
            # get_device_info_walk_oids() additionally walks the parent tables so that
            # sensors indexed at .2 or higher are also discovered.
            self.OID_ENV_TEMP_VALUE,
            self.OID_ENV_TEMP_STATE,
            self.OID_ENV_FAN_STATE,
            # CPU — CISCOSB-rndMng MIB scalar GET (instance .0)
            self.OID_CPU_1MIN,
            # Memory — CISCOSB-rndMng MIB scalar GETs (preferred over hrStorageTable)
            self.OID_RL_FREE_MEMORY,
            self.OID_RL_TOTAL_MEMORY,
        ]

    def get_device_info_walk_oids(self) -> List[str]:
        """Return parent table OIDs to walk for device info environmental data.

        Called by ``polling_engine._poll_device_info()`` after the scalar
        ``get_multiple()`` GET.  The walked results are merged into snmp_data so
        that ``parse_device_info()`` can find sensor values at any table index,
        not just the fixed index .1 used by ``get_device_info_oids()``.

        CBS350 firmware assigns sensor indices inconsistently: some models put
        the board temperature at index .2 while the .1 slot returns
        ``noSuchInstance``, causing the scalar GET to silently yield nothing.
        Walking the parent column OID guarantees discovery regardless of index.

        The same applies to the PoE pethMainPseTable: CBS350 in stack mode may
        report PoE at a group index other than .1 (e.g. the physical unit's
        slot number when stacking is pre-configured in firmware).

        Memory is collected from HOST-RESOURCES-MIB hrStorageTable: CBS350 does
        not expose memory via CISCOSB-specific OIDs, so we walk the four table
        columns needed to compute RAM utilisation (type, units, size, used).

        ENTITY-SENSOR-MIB columns are walked as tertiary fallback for temperature
        on CBS350 firmware that does not implement CISCO-ENVMON-MIB or CISCOSB-ENVMON-MIB.
        """
        return [
            # CISCOSB-HWENVIROMENT rlEnvFanDataTemp (.83.5.1.1.2) — PRIMARY temperature path.
            # Confirmed working by LibreNMS ciscosb.yaml.  Value is direct Celsius.
            self.OID_RL_HW_FAN_DATA_TEMP_BASE,
            # CISCOSB-HWENVIROMENT rlEnvMonFanState (.83.1.1.1.3) — PRIMARY fan state path.
            # Values: 1=normal, 2=warning, 3=critical, 4=shutdown, 5=notPresent, 6=notFunctioning.
            self.OID_RL_HW_FAN_STATE_BASE,
            # ciscoEnvMonTemperatureStatusValue table (all sensor indices)
            self.OID_ENV_TEMP_VALUE_BASE,
            # ciscoEnvMonFanState table (all fan indices) — CISCO-ENVMON-MIB path
            self.OID_ENV_FAN_STATE_BASE,
            # rlEnvMonDescr table — legacy CISCOSB-ENVMON-MIB (.101.13): sensor description strings
            self.OID_RL_ENV_DESCR_BASE,
            # rlEnvMonCurrentState table — legacy CISCOSB-ENVMON-MIB (.101.13): per-sensor state (1-6)
            self.OID_RL_ENV_STATE_BASE,
            # HOST-RESOURCES-MIB hrStorageTable columns for memory
            self.OID_HR_STORAGE_TYPE,
            self.OID_HR_STORAGE_UNITS,
            self.OID_HR_STORAGE_SIZE,
            self.OID_HR_STORAGE_USED,
            # ENTITY-SENSOR-MIB columns — tertiary fallback for temperature on CBS350
            self.OID_ENT_SENSOR_TYPE,
            self.OID_ENT_SENSOR_SCALE,
            self.OID_ENT_SENSOR_VALUE,
            # ENTITY-MIB physical description — used to identify sensor indices by keyword
            # ("temp"/"fan") when entPhySensorType is not set to expected values on CBS350.
            self.OID_ENT_PHYS_DESCR,
        ]

    def parse_device_info(self, snmp_data: Dict[str, Any]) -> DeviceInfo:
        """Parse device information from SNMP data."""
        sys_descr = str(snmp_data.get(self.OID_SYS_DESCR, "Unknown"))
        sys_name = str(snmp_data.get(self.OID_SYS_NAME, "Unknown"))
        sys_uptime = int(snmp_data.get(self.OID_SYS_UPTIME, 0))
        
        # For CBS350-24FP-4G: 24 PoE ports + 4 SFP ports = 28 physical ports
        # Don't use if_number as it includes virtual interfaces
        # Instead, count actual physical ethernet ports from interface descriptions,
        # tracking PoE-capable (GE/GigE/FA) and uplink (TE/TenGigE) ports separately.
        poe_port_count = 0
        uplink_port_count = 0
        for oid, value in snmp_data.items():
            if self.OID_IF_DESCR in oid and not oid.endswith(self.OID_IF_DESCR):
                descr = str(value).lower()
                if not any(x in descr for x in ['vlan', 'management', 'null', 'loopback', 'port-channel']):
                    # PoE-capable copper access ports (GigabitEthernet / GE / FA prefix)
                    if descr.startswith(('gi', 'ge', 'gigabit', 'fa')):
                        poe_port_count += 1
                    # SFP/SFP+ fiber uplink ports (TenGigabitEthernet / TE prefix)
                    elif descr.startswith('te'):
                        uplink_port_count += 1
        physical_port_count = poe_port_count + uplink_port_count

        # If we couldn't count ports, parse the CBS350 model string from sys_descr.
        # CBS350-{access}-{uplink}[G|X] format (e.g. CBS350-48P-4G → 48+4=52,
        # CBS350-48FP-4X → 48+4=52, CBS350-24FP-4G → 24+4=28).
        # Never fall back to IF_NUMBER because that value includes VLAN
        # sub-interfaces and can be 200+.
        if physical_port_count == 0:
            m = re.search(r'CBS350-(\d+)[A-Za-z]*-(\d+)[GX]', sys_descr, re.IGNORECASE)
            if m:
                poe_port_count = int(m.group(1))
                uplink_port_count = int(m.group(2))
                physical_port_count = poe_port_count + uplink_port_count
            else:
                m2 = re.search(r'CBS350-(\d+)', sys_descr, re.IGNORECASE)
                if m2:
                    # Assume 4 SFP uplinks when not specified in model string
                    poe_port_count = int(m2.group(1))
                    uplink_port_count = 4
                    physical_port_count = poe_port_count + uplink_port_count
                # If model still can't be determined, leave as 0 so the worker
                # falls back to counting live ports from port_info (parse_port_info).

        # Store for use by parse_port_info() to cap phantom stack-member ports.
        self._expected_port_count = physical_port_count
        # Store PoE-capable port count for use by get_port_get_oids().
        # SFP/SFP+ uplink ports (counted in uplink_port_count) are NOT PoE capable
        # and must not be included in the pethPsePortTable GET loop — they always
        # return noSuchInstance and each wasted GET adds SNMP agent CPU load.
        self._poe_port_count = poe_port_count

        # ── Environmental: build CISCOSB rlEnvMonDescr index map ────────────
        # rlEnvMonDescr column (.2) holds a description string per sensor index:
        #   e.g. "FAN 1", "FAN 2", "TEMP 1", "PSU 1"
        # Used below to identify which sensors are fans vs. temperature.
        # On devices that do not implement CISCOSB-ENVMON-MIB the dict is empty
        # and no CISCOSB-based fan/temperature data will be collected.
        rl_env_descr_by_idx: Dict[str, str] = {}
        for key, tv in snmp_data.items():
            if key.startswith(self.OID_RL_ENV_DESCR_BASE + '.'):
                idx = key[len(self.OID_RL_ENV_DESCR_BASE) + 1:]
                rl_env_descr_by_idx[idx] = str(tv).lower()

        # ── Environmental: temperature (index-agnostic scan) ────────────────
        # Priority order:
        #   1. CISCOSB-HWENVIROMENT rlEnvFanDataTemp (.101.83.5.1.1.2) — PRIMARY.
        #      Confirmed working by LibreNMS ciscosb.yaml.  Value is direct Celsius.
        #   2. CISCO-ENVMON-MIB walk (ciscoEnvMonTemperatureStatusValue table)
        #   3. ENTITY-SENSOR-MIB + ENTITY-MIB description-based detection (tertiary)

        # Pre-build ENTITY-SENSOR-MIB / ENTITY-MIB index maps (used for both
        # temperature and fan detection below).  Maps are keyed by sensor index string.
        _ent_phys_descr: Dict[str, str] = {}
        _ent_type: Dict[str, int] = {}
        _ent_scale: Dict[str, int] = {}
        _ent_value: Dict[str, int] = {}
        for _k, _v in snmp_data.items():
            if _k.startswith(self.OID_ENT_PHYS_DESCR + '.'):
                _ent_phys_descr[_k[len(self.OID_ENT_PHYS_DESCR) + 1:]] = str(_v).lower()
            elif _k.startswith(self.OID_ENT_SENSOR_TYPE + '.'):
                try:
                    _ent_type[_k[len(self.OID_ENT_SENSOR_TYPE) + 1:]] = int(_v)
                except Exception:
                    pass
            elif _k.startswith(self.OID_ENT_SENSOR_SCALE + '.'):
                try:
                    _ent_scale[_k[len(self.OID_ENT_SENSOR_SCALE) + 1:]] = int(_v)
                except Exception:
                    pass
            elif _k.startswith(self.OID_ENT_SENSOR_VALUE + '.'):
                try:
                    _ent_value[_k[len(self.OID_ENT_SENSOR_VALUE) + 1:]] = int(_v)
                except Exception:
                    pass

        temperature_c = None

        # ── Path 1: CISCOSB-HWENVIROMENT rlEnvFanDataTemp (.101.83.5.1.1.2) ──
        # Walk result keys look like: OID_RL_HW_FAN_DATA_TEMP_BASE.INDEX
        # Value is direct Celsius integer (no scaling needed).
        try:
            for key, tv in snmp_data.items():
                if key.startswith(self.OID_RL_HW_FAN_DATA_TEMP_BASE + '.'):
                    try:
                        t = int(tv)
                        if 0 < t < 200:
                            temperature_c = float(t)
                            break
                    except Exception:
                        continue
        except Exception:
            pass
        # ── Path 2: CISCO-ENVMON-MIB ciscoEnvMonTemperatureStatusValue ──────
        if temperature_c is None:
            try:
                for key, tv in snmp_data.items():
                    if (key == self.OID_ENV_TEMP_VALUE
                            or key.startswith(self.OID_ENV_TEMP_VALUE_BASE + '.')):
                        try:
                            t = int(tv)
                            if 0 < t < 200:
                                temperature_c = float(t)
                                break
                        except Exception:
                            continue
            except Exception:
                pass

        # ── Path 3: ENTITY-SENSOR-MIB + ENTITY-MIB description-based (tertiary) ──
        #
        # Discovery strategy:
        #   a. entPhysicalDescr contains "temp" (case-insensitive), OR
        #   b. entPhySensorType == 8 (celsius) — standard RFC 3433
        #   Apply entPhySensorScale: 8=milli → ÷1000; 9=units → as-is.
        if temperature_c is None:
            try:
                # Determine candidate temperature indices
                candidate_temp_idxs = set()
                for idx, descr in _ent_phys_descr.items():
                    if 'temp' in descr:
                        candidate_temp_idxs.add(idx)
                # Also accept indices where entPhySensorType==8 (celsius) per RFC 3433
                for idx, stype in _ent_type.items():
                    if stype == 8:
                        candidate_temp_idxs.add(idx)
                for idx in candidate_temp_idxs:
                    val = _ent_value.get(idx)
                    if val is None:
                        continue
                    scale = _ent_scale.get(idx, 9)  # default 9=units
                    # entPhySensorScale 8=milli → divide by 1000; 9=units → use as-is
                    t = round(val / 1000) if scale == 8 else val
                    if 0 < t < 200:
                        temperature_c = float(t)
                        break
            except Exception:
                pass

        # ── Environmental: fan state (index-agnostic scan, worst state wins) ─
        # Priority order:
        #   1. CISCOSB-HWENVIROMENT rlEnvMonFanState (.101.83.1.1.1.3) — PRIMARY.
        #      Confirmed working by LibreNMS ciscosb.yaml.
        #   2. CISCO-ENVMON-MIB walk (ciscoEnvMonFanState table)
        #   3. Legacy CISCOSB-ENVMON-MIB rlEnvMonCurrentState (.101.13) — filter by "fan" descr
        #   4. ENTITY-SENSOR-MIB: entPhysicalDescr contains "fan"
        fan_status = None
        _fan_worst = 0

        # ── Path 1: CISCOSB-HWENVIROMENT rlEnvMonFanState (.101.83.1.1.1.3) ──
        try:
            for key, fv in snmp_data.items():
                if key.startswith(self.OID_RL_HW_FAN_STATE_BASE + '.'):
                    try:
                        iv = int(fv)
                        if 1 <= iv <= 6 and iv != 5:  # 5=notPresent → skip
                            # Map to severity: 1=normal(OK), 2=warning, 3-4=critical, 6=notFunctioning(critical)
                            sev = 1 if iv == 1 else (2 if iv == 2 else 3)
                            if sev > _fan_worst:
                                _fan_worst = sev
                    except Exception:
                        pass
        except Exception:
            pass
        # Map back to fan state strings using worst severity
        if _fan_worst > 0:
            fan_status = 'OK' if _fan_worst == 1 else ('WARNING' if _fan_worst == 2 else 'CRITICAL')

        # ── Paths 2-4: existing detection as fallbacks ───────────────────────
        if _fan_worst == 0:
            try:
                for key, fv in snmp_data.items():
                    if (key == self.OID_ENV_FAN_STATE
                            or key.startswith(self.OID_ENV_FAN_STATE_BASE + '.')):
                        # CISCO-ENVMON-MIB path — always fan state
                        try:
                            iv = int(fv)
                            if 1 <= iv <= 4 and iv > _fan_worst:
                                _fan_worst = iv
                        except Exception:
                            pass
                    elif key.startswith(self.OID_RL_ENV_STATE_BASE + '.'):
                        # Legacy CISCOSB-ENVMON-MIB path: use only fan-described entries when
                        # descriptions are available; fall back to all entries when not.
                        idx = key[len(self.OID_RL_ENV_STATE_BASE) + 1:]
                        descr = rl_env_descr_by_idx.get(idx, '')
                        is_fan = 'fan' in descr if descr else not rl_env_descr_by_idx
                        if is_fan:
                            try:
                                iv = int(fv)
                                # 1=normal,2=warning,3=critical,4=shutdown — higher severity wins
                                if 1 <= iv <= 4 and iv > _fan_worst:
                                    _fan_worst = iv
                            except Exception:
                                pass
                # ENTITY-SENSOR-MIB fan state via entPhysicalDescr (quaternary fallback)
                if _fan_worst == 0 and _ent_phys_descr:
                    for idx, descr in _ent_phys_descr.items():
                        if 'fan' not in descr:
                            continue
                        val = _ent_value.get(idx)
                        if val is None:
                            continue
                        # entPhySensorType 12=truthvalue: 1=true(ok), 2=false(fail)
                        # Other types: non-zero RPM means running → assume OK
                        stype = _ent_type.get(idx, 0)
                        if stype == 12:
                            _fan_worst = 1 if val == 1 else 3  # 1=ok, 2=failed→critical
                        elif val > 0:
                            _fan_worst = 1  # any positive RPM/value → OK
                if _fan_worst > 0:
                    fan_status = self._FAN_STATE_MAP.get(_fan_worst, 'N/A')
            except Exception:
                pass

        return DeviceInfo(
            system_description=sys_descr,
            system_name=sys_name,
            system_uptime=sys_uptime,
            total_ports=physical_port_count,
            fan_status=fan_status,
            temperature_c=temperature_c,
            # poe_nominal_w / poe_consumed_w: intentionally None.
            # CBS350 firmware does not respond reliably to pethMainPseTable
            # GETBULK queries (same timeout issue as pethPsePortTable columns).
            # Per-port PoE status (Güç Veriyor / Arıza / Pasif) is collected
            # via individual GET OIDs in get_port_get_oids() instead.
            poe_nominal_w=None,
            poe_consumed_w=None,
            cpu_1min=self._parse_cpu_1min(snmp_data),
            memory_usage=self._parse_memory_usage(snmp_data),
        )

    def _parse_cpu_1min(self, snmp_data: Dict[str, Any]) -> Optional[int]:
        """Parse 1-minute CPU utilisation from CISCOSB-rndMng MIB.

        OID: 1.3.6.1.4.1.9.6.1.101.1.8.0 = rlCpuUtilDuringLastMinute
        Returns integer 0-100 or None if unavailable.
        """
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
        """Parse memory utilisation % for CBS350.

        Tries CISCOSB-rndMng scalar OIDs first (rlFreeMemory / rlTotalMemory),
        which are the native CBS350 memory counters.  Falls back to the
        HOST-RESOURCES-MIB hrStorageTable walk when the CISCOSB scalars are
        absent (e.g. older firmware or non-CISCOSB device).

        CISCOSB formula: usage% = (total - free) / total * 100
        hrStorage formula: usage% = used / size * 100

        Returns float 0.0-100.0 or None if neither method yields data.
        """
        # ── Primary: CISCOSB-rndMng scalar OIDs ─────────────────────────────
        try:
            free_val  = snmp_data.get(self.OID_RL_FREE_MEMORY)
            total_val = snmp_data.get(self.OID_RL_TOTAL_MEMORY)
            if free_val is not None and total_val is not None:
                free  = int(free_val)
                total = int(total_val)
                if total > 0:
                    used = total - free
                    return round(max(used, 0) / total * 100, 1)
        except (TypeError, ValueError):
            pass

        # ── Fallback: HOST-RESOURCES-MIB hrStorageTable ─────────────────────
        # Build per-index maps from the walked table columns.
        # OID keys look like: '1.3.6.1.2.1.25.2.3.1.2.<index>'
        type_by_idx:  Dict[str, str] = {}
        size_by_idx:  Dict[str, int] = {}
        used_by_idx:  Dict[str, int] = {}

        for oid, val in snmp_data.items():
            if oid.startswith(self.OID_HR_STORAGE_TYPE + '.'):
                idx = oid[len(self.OID_HR_STORAGE_TYPE) + 1:]
                try:
                    # Value may be an OID object or a string like "1.3.6.1.2.1.25.2.1.2"
                    type_by_idx[idx] = str(val)
                except Exception:
                    pass
            elif oid.startswith(self.OID_HR_STORAGE_SIZE + '.'):
                idx = oid[len(self.OID_HR_STORAGE_SIZE) + 1:]
                try:
                    size_by_idx[idx] = int(val)
                except (TypeError, ValueError):
                    pass
            elif oid.startswith(self.OID_HR_STORAGE_USED + '.'):
                idx = oid[len(self.OID_HR_STORAGE_USED) + 1:]
                try:
                    used_by_idx[idx] = int(val)
                except (TypeError, ValueError):
                    pass

        for idx, storage_type in type_by_idx.items():
            # hrStorageRam type OID can appear as full OID or just the last segment
            if self.OID_HR_STORAGE_RAM in storage_type or storage_type == '2':
                size = size_by_idx.get(idx)
                used = used_by_idx.get(idx)
                # Only return a value when used > 0.  CBS350 firmware always reports
                # hrStorageUsed = 0 (the device does not expose real memory usage via
                # HOST-RESOURCES-MIB), which would produce a misleading flat 0% chart.
                # A genuinely idle device will have used > 0 in practice.
                if size and used is not None and size > 0 and used > 0:
                    return round(used / size * 100, 1)
        return None
    
    def get_port_info_oids(self) -> List[str]:
        """Get OIDs for port information (these are walked via GETBULK).

        When ``_expected_port_count > 0`` (model string recognised by
        ``parse_device_info``), the interface table columns are returned by
        ``get_if_column_oids()`` instead and walked with an early-stop index
        to skip phantom stack-unit interfaces.  In that case this method
        returns only the Q-BRIDGE VLAN static entry OID (which is indexed by
        VLAN ID, NOT by ifIndex, so early stop must not be applied to it).

        When ``_expected_port_count == 0`` (model unrecognised), falls back to
        walking the full ifTable / ifXTable parents together with Q-BRIDGE —
        the original three-OID approach.
        """
        if self._expected_port_count > 0:
            # Individual interface columns are handled by get_if_column_oids().
            # Return only the VLAN-indexed Q-BRIDGE table here (full walk).
            return ['1.3.6.1.2.1.17.7.1.4.2.1']  # dot1qVlanStaticEntry
        # Fallback: full parent-table walk (model string not recognised).
        return [
            self.OID_IF_TABLE,              # entire ifTable  (columns .2 – .22)
            '1.3.6.1.2.1.31.1.1.1',         # entire ifXTable (columns .1 – .18)
            '1.3.6.1.2.1.17.7.1.4.2.1',     # Q-BRIDGE VLAN static entry
            '1.3.6.1.2.1.105.1.1.1',         # pethPsePortTable (per-port PoE)
        ]

    def get_if_column_oids(self) -> List[str]:
        """Return individual ifTable/ifXTable column OIDs for limited-index walks.

        Used by the polling engine when ``get_max_port_ifindex() > 0``.  Each
        OID is a single table COLUMN (not a parent table), so the GETBULK walk
        only visits rows for that column.  Combined with ``stop_at_index`` in
        ``SNMPClient.get_bulk()``, this limits the walk to unit-1 interfaces
        (ifIndex 1..expected_port_count) and avoids collecting the phantom
        unit-2/3/4 interfaces present in CBS350 stack-mode ifTable.

        CBS350-48FP in stack mode: 4 × 52 = 208 rows per column.
        With stop_at_index=52: each column walk stops after 2 GETBULK requests
        instead of 8, reducing round-trips from ~167 to ~36 (a 4.6× saving).
        For devices with ~200 ms RTT this cuts poll time from ~30 s to ~8 s.

        Returns an empty list when ``_expected_port_count == 0`` (model not
        recognised yet); the polling engine then falls back to the full
        parent-table walk via ``get_port_info_oids()``.
        """
        if self._expected_port_count == 0:
            _log.debug(
                'CBS350 get_if_column_oids: _expected_port_count not yet set '
                '(model string unrecognised or parse_device_info not called); '
                'falling back to full parent-table walk via get_port_info_oids()'
            )
            return []
        return [
            # ── ifTable columns (1.3.6.1.2.1.2.2.1.<col>) ──────────────────
            self.OID_IF_DESCR,          # .2  interface description / name
            self.OID_IF_TYPE,           # .3  ifType (ethernetCsmacd = 6)
            self.OID_IF_MTU,            # .4  MTU
            self.OID_IF_SPEED,          # .5  ifSpeed (32-bit, Bps)
            self.OID_IF_PHYS_ADDRESS,   # .6  MAC address
            self.OID_IF_ADMIN_STATUS,   # .7  admin status (1=up, 2=down)
            self.OID_IF_OPER_STATUS,    # .8  operational status
            self.OID_IF_IN_OCTETS,      # .10 inbound octets (32-bit)
            self.OID_IF_IN_DISCARDS,    # .13 inbound discards
            self.OID_IF_IN_ERRORS,      # .14 inbound errors
            self.OID_IF_OUT_OCTETS,     # .16 outbound octets (32-bit)
            self.OID_IF_OUT_DISCARDS,   # .19 outbound discards
            self.OID_IF_OUT_ERRORS,     # .20 outbound errors
            # ── ifXTable columns (1.3.6.1.2.1.31.1.1.1.<col>) ──────────────
            self.OID_IF_NAME,           # .1  interface name (short)
            self.OID_IF_HIGH_SPEED,     # .15 ifHighSpeed (Mbps, 64-bit safe)
            self.OID_IF_ALIAS,          # .18 ifAlias (description string)
            self.OID_IF_HC_IN_OCTETS,   # .6  ifHCInOctets  (64-bit)
            self.OID_IF_HC_OUT_OCTETS,  # .10 ifHCOutOctets (64-bit)
        ]

    def get_max_port_ifindex(self) -> int:
        """Maximum ifIndex of unit-1 physical ports for early walk termination.

        CBS350 in stack mode pre-populates ifTable for all configured stack
        units (up to 4).  A CBS350-48FP-4G/4X has 4 × 52 = 208 ifTable rows,
        but only ifIndex 1..52 belong to the physically present unit-1.

        Returning ``_expected_port_count`` here tells the polling engine to
        pass ``stop_at_index=N`` to ``SNMPClient.get_bulk()`` for each
        interface column OID.  This cuts the number of GETBULK round-trips
        by up to 4× for stack-configured switches.

        Returns 0 when the model string is not yet known; the engine then
        uses the full unbounded walk as a safe fallback.
        """
        return self._expected_port_count

    def get_port_get_oids(self, num_ports: int = 28) -> List[str]:
        """Return per-port pethPsePortTable GET OIDs for PoE detect status and class.

        CBS350 firmware often does not respond to GETBULK for pethPsePortTable,
        causing 9-10 second SNMP timeouts per column OID when those columns are
        included in the GETBULK walk.  Individual GET requests (one per port) are
        fast and reliable on all CBS350 firmware versions.

        This method uses ``_poe_port_count`` (set by ``parse_device_info()``) to
        restrict the query range to PoE-capable copper ports only.  SFP/SFP+
        uplink ports (tracked separately in ``_poe_port_count`` vs
        ``_expected_port_count``) are NOT included because they always return
        ``noSuchInstance`` — querying them wastes SNMP round-trips and adds CPU
        load to the CBS350's SNMP agent, contributing to GETBULK timeouts on the
        subsequent MAC-table walk.  For a CBS350-48FP-4X this reduces the query
        count from 104 (52 × 2) to 96 (48 × 2).
        """
        # Use PoE-capable port count if available; fall back to total port count.
        poe_limit = self._poe_port_count if self._poe_port_count > 0 else self._expected_port_count
        if not poe_limit:
            _log.debug(
                'CBS350 get_port_get_oids: _expected_port_count not yet set '
                '(parse_device_info not called or model unrecognised); '
                'skipping per-port pethPsePortTable GETs'
            )
            return []
        oids = []
        for port_idx in range(1, poe_limit + 1):
            oids.append(f"{self.OID_PETH_PORT_DETECT}.1.{port_idx}")
            oids.append(f"{self.OID_PETH_PORT_CLASS}.1.{port_idx}")
        return oids

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

        def _bitmap_ports(mask_val) -> set:
            """OctetString bitmap → set of 1-based port numbers.

            Port count is derived from the mask length (1 byte = 8 ports) so that
            all CBS350 models are handled correctly:
              - CBS350-24FP (28 ports):  mask is 4 bytes → ports 1-32 scanned
              - CBS350-48FP (52 ports):  mask is 7 bytes → ports 1-56 scanned
            Using the fixed default of 28 caused ports 29-52 on 48-port switches
            to be invisible in the VLAN bitmaps, leaving their vlan_id as None
            and preserving stale 'ETHERNET' type labels.
            """
            raw = _octetstring_to_bytes(mask_val)
            if not raw:
                return set()
            result = set()
            # The loop upper bound is exactly len(raw) * 8, so byte_pos always
            # stays in [0, len(raw)-1] and no out-of-range access can occur.
            # The explicit guard is kept for defensive clarity.
            for i in range(1, len(raw) * 8 + 1):
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
                if dl.startswith(('gi', 'ge', 'gigabit', 'fa', 'te')):
                    # Skip management, virtual interfaces, and port-channels
                    if not any(x in dl for x in ['vlan', 'management', 'null', 'loopback', 'port-channel']):
                        # ── Stack-mode phantom port filter ────────────────────────
                        # CBS350-48FP in stack mode pre-populates interfaces for
                        # all configured stack units (up to 4) even when only
                        # unit 1 is physically present.  In stack mode, interface
                        # names use the <unit>/<slot>/<port> convention:
                        #   Unit 1 (real):    Gi1/0/1 … Gi1/0/48, Te1/0/1 … Te1/0/4
                        #   Units 2-4 (ghost):Gi2/0/1 … Gi4/0/48
                        # Non-stacked CBS350 (e.g. 24-port models) uses flat names
                        # (GE1, GE2, …) with no '/' — not affected by this filter.
                        if '/' in dl:
                            m_unit = re.search(r'(\d+)/', dl)
                            if m_unit and int(m_unit.group(1)) != 1:
                                continue  # phantom stack-unit interface, skip
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

        # ── Secondary safeguard: cap by model-derived port count ────────────────
        # The primary filter above (unit-number check in interface name) handles
        # CBS350 stack mode where names use the <unit>/<slot>/<port> scheme.
        # This secondary cap catches any remaining edge cases where phantom
        # interfaces use flat numbering and slipped through the name filter.
        _total_collected = len(ports)
        if self._expected_port_count > 0 and _total_collected > self._expected_port_count:
            keep_indices = sorted(ports.keys())[:self._expected_port_count]
            ports = {idx: ports[idx] for idx in keep_indices}
            _log.info(
                'CBS350: capped to %d ports (model limit); removed %d phantom '
                'stack-unit interface(s)',
                self._expected_port_count,
                _total_collected - self._expected_port_count,
            )

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

        # Build ifIndex → port_number mapping for use in parse_mac_table.
        # For CBS350, port_number == ifIndex, but we maintain the map explicitly
        # for consistency with the C9200/C9300 pattern used in parse_mac_table.
        self._if_to_port = {if_index: ports[if_index]['port_number'] for if_index in ports}

        # Pre-populate _port_vlan_map from VLAN bitmap data so parse_mac_table
        # can use it for AP trunk detection even without a prior MAC walk.
        for if_index, d in ports.items():
            vlan = d.get('vlan_id')
            if vlan and vlan > 1:
                self._port_vlan_map[d['port_number']] = vlan

        # ── Per-port PoE (pethPsePortTable, RFC 3621) ───────────────────────
        # Index format: {GroupIndex}.{PortIndex}  (GroupIndex=1 for CBS350)
        # Only collect GroupIndex=1 entries; ignore stack-unit rows (Group 2+).
        # CBS350 PortIndex == ifIndex, so we can directly key by ifIndex.
        # NOTE: OID_RL_POE_PORT_MW (CISCO-SB proprietary milliwatt OID) and bulk
        #       walks of pethPsePortTable columns are intentionally omitted: CBS350
        #       firmware often does not respond to GETBULK for these OIDs, causing
        #       9-10 second timeouts per OID.  Instead, per-port individual GETs are
        #       issued via get_port_get_oids() which is fast and reliable on all
        #       CBS350 firmware.  Per-port watt display is omitted; status (Güç
        #       Veriyor / Arıza / Pasif) and class are reported via snmp_port_detail.php.
        poe_detect_map:  Dict[int, int] = {}   # port_idx → detect status integer
        poe_class_map:   Dict[int, int] = {}   # port_idx → class enum integer

        for oid, value in snmp_data.items():
            # RFC 3621 pethPsePortTable: suffix format is {GroupIdx}.{PortIdx}
            for col_oid, target_map in (
                (self.OID_PETH_PORT_DETECT, poe_detect_map),
                (self.OID_PETH_PORT_CLASS,  poe_class_map),
            ):
                if oid.startswith(col_oid + '.'):
                    suffix = oid[len(col_oid) + 1:]  # e.g. "1.5" → GroupIdx.PortIdx
                    parts = suffix.split('.')
                    if len(parts) >= 2:
                        try:
                            group_idx = int(parts[0])
                            port_idx  = int(parts[1])
                            if group_idx == 1:  # only unit-1 / single PSE module
                                try:
                                    target_map[port_idx] = int(value)
                                except (ValueError, TypeError):
                                    pass
                        except (ValueError, IndexError):
                            pass

        # Attach PoE data to each port dict.
        # Only PoE-capable ports (port index ≤ nominal PoE port count for the model)
        # will have non-None values; SFP uplink ports get None (not PoE capable).
        for if_index, port_d in ports.items():
            detect_val = poe_detect_map.get(if_index)
            if detect_val is not None:
                # pethPsePortDetectStatus: 3 = deliveringPower, 4/6 = fault
                is_delivering = (detect_val == 3)
                is_fault      = detect_val in (4, 6)  # 4=fault, 6=otherFault
                port_d['poe_detecting'] = is_delivering
                # poe_power_mw: -1 signals fault (UI shows "Arıza"); 0 means
                # no watt data (milliwatt OID not queried — UI shows "-").
                port_d['poe_power_mw'] = -1 if is_fault else 0
                port_d['poe_class'] = poe_class_map.get(if_index)
            # If detect_val is None the port is not in pethPsePortTable (e.g. SFP);
            # poe_detecting / poe_power_mw / poe_class remain None (default from PortInfo).

        # Convert to PortInfo objects
        port_list = []
        for port_data in ports.values():
            port_list.append(PortInfo(**port_data))
        
        return port_list

    def get_mac_table_oids(self) -> List[str]:
        """Get OIDs for MAC address table (primary walk, Q-BRIDGE preferred).

        Returns only the Q-BRIDGE VLAN-aware FDB and the bridge-port→ifIndex
        mapping.  The plain dot1dTpFdb (``OID_DOT1D_TP_FDB_PORT``) is NOT
        included here; it is available via ``get_mac_fallback_oids()`` and
        walked only when the Q-BRIDGE OID returns nothing (two-phase approach
        in ``polling_engine._poll_mac_table()``).

        Rationale: on every CBS350 in normal operation, ``dot1qTpFdb``
        (Q-BRIDGE) is populated.  Walking ``dot1dTpFdb`` unconditionally
        wastes 1-3s per poll cycle because it contains the same MACs but
        without VLAN information, and its result is immediately discarded by
        ``parse_mac_table()`` when Q-BRIDGE already provided data.

        CBS350 Q-BRIDGE FDB OID is indexed by VLAN+MAC, providing both VLAN
        and port for every learned MAC in a single walk.
        """
        return [
            self.OID_DOT1Q_FDB_PORT,   # VLAN-aware FDB (preferred)
            self.OID_DOT1D_BASE_PORT,  # bridge-port → ifIndex mapping
        ]

    def get_mac_fallback_oids(self) -> List[str]:
        """Fallback MAC table OIDs used when the Q-BRIDGE walk returns nothing.

        ``dot1dTpFdb`` is the classic bridge FDB without VLAN information.
        It is only walked by ``polling_engine._poll_mac_table()`` when the
        Q-BRIDGE OID (``OID_DOT1Q_FDB_PORT``) yielded no entries in the
        primary walk, indicating the switch may not support the Q-BRIDGE MIB
        (older firmware or non-standard CBS350 variant).
        """
        return [self.OID_DOT1D_TP_FDB_PORT]

    def parse_mac_table(self, snmp_data: Dict[str, Any]) -> Dict[int, List[str]]:
        """Parse MAC address table with VLAN-aware AP trunk detection.

        Uses ``dot1qTpFdbPort`` (Q-BRIDGE MIB) where the OID index encodes
        both the VLAN ID and the MAC address::

            1.3.6.1.2.1.17.7.1.2.2.1.2.<vlan>.<m1>.<m2>.<m3>.<m4>.<m5>.<m6>

        AP trunk detection (same rule as C9200/C9300):
          - A port with MACs in AP_VLAN (70) **and** in other VLANs is an AP
            uplink carrying the physical AP MAC on VLAN 70 plus wireless-client
            MACs on other VLANs (VLAN 30, 50, …).
          - For such ports, only the VLAN-70 MACs are returned.  This prevents
            randomised/rotating client MACs from triggering false "MAC moved"
            alarms.
        """
        # ── Bridge-port → ifIndex mapping ───────────────────────────────────
        bridge_port_to_if: Dict[int, int] = {}
        for oid, value in snmp_data.items():
            if oid.startswith(self.OID_DOT1D_BASE_PORT + '.'):
                try:
                    bp = int(oid.split('.')[-1])
                    if_idx = int(str(value))
                    bridge_port_to_if[bp] = if_idx
                except Exception:
                    pass

        # ── Q-BRIDGE VLAN-aware FDB walk ────────────────────────────────────
        # result_sets[port_num] = set of (mac, vlan_id) tuples
        result_sets: Dict[int, set] = {}
        q_bridge_used = False

        for oid, value in snmp_data.items():
            if not oid.startswith(self.OID_DOT1Q_FDB_PORT + '.'):
                continue
            try:
                parts = oid.split('.')
                # The base OID has 12 components; indices follow as:
                # ….<vlan_id>.<mac_oct1>.<mac_oct2>.<mac_oct3>.<mac_oct4>.<mac_oct5>.<mac_oct6>
                # so vlan_id is at position -7 and MAC octets are at positions -6..-1.
                vlan_id = int(parts[-7])
                mac_parts = parts[-6:]
                mac = ':'.join(f'{int(x):02x}' for x in mac_parts)
                bp = int(str(value))
                if bp == 0:
                    continue
                # Resolve bridge-port → ifIndex → port_number
                if_idx = bridge_port_to_if.get(bp, bp)  # fallback: bp == ifIndex
                port_num = self._if_to_port.get(if_idx, if_idx)
                result_sets.setdefault(port_num, set()).add((mac, vlan_id))
                q_bridge_used = True
            except Exception:
                pass

        if not q_bridge_used:
            # Fallback: use plain dot1dTpFdbPort (no VLAN info — cannot do AP
            # trunk filtering, but at least return MACs as before).
            _log.debug('CBS350: dot1qTpFdb empty, falling back to dot1dTpFdb')
            return super().parse_mac_table(snmp_data)

        # ── AP trunk detection ───────────────────────────────────────────────
        # Same logic as CiscoC9200Mapper.collect_mac_with_vlan_contexts.
        for port_num, mac_vlan_set in result_sets.items():
            vlans_on_port = {vlan for _mac, vlan in mac_vlan_set}
            if self.AP_VLAN in vlans_on_port and (vlans_on_port & self.AP_COMPANION_VLANS):
                # AP trunk port: force VLAN map to AP_VLAN so only physical MAC
                # is returned, suppressing rotating WiFi-client MACs.
                self._port_vlan_map[port_num] = self.AP_VLAN
                _log.debug(
                    'CBS350 AP trunk detected: port %d → VLAN %d (AP native VLAN)',
                    port_num, self.AP_VLAN
                )
            else:
                best_vlan = max(vlans_on_port) if vlans_on_port else None
                if best_vlan and best_vlan > 1:
                    self._port_vlan_map[port_num] = best_vlan

        # ── Build final result (filter each port to its own VLAN's MACs) ────
        result: Dict[int, List[str]] = {}
        for port_num, mac_vlan_set in result_sets.items():
            port_vlan = self._port_vlan_map.get(port_num)
            if port_vlan:
                filtered = sorted({mac for mac, vlan in mac_vlan_set if vlan == port_vlan})
                if filtered:
                    result[port_num] = filtered
            # Ports with no VLAN mapping (trunk/fiber uplinks) are intentionally
            # excluded from the MAC result.  Trunk ports carry multiple VLANs and
            # their FDB entries are predominantly client MACs from attached
            # switches/APs (including all WiFi VLAN 70 clients), not directly
            # connected devices.  Assigning those MACs to uplink ports would
            # pollute the DB with hundreds of unrelated addresses and trigger
            # false MAC-move alarms whenever a WiFi client roams.
            # (Before this change the "else" branch showed all MACs on any
            # port whose VLAN was unknown; now trunk/uplink ports are skipped.)

        _log.info(
            'CBS350 VLAN-aware MAC table: %d ports with MACs (%d total MACs)',
            len(result), sum(len(v) for v in result.values())
        )
        return result
