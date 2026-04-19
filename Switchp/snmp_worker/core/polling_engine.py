"""
SNMP Polling Engine - Core polling logic for network devices.
Handles parallel polling of multiple devices.
"""

import logging
import json
import time
import random
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from concurrent.futures import Future, ThreadPoolExecutor, as_completed

from config.config_loader import Config, DeviceConfig
from core.snmp_client import SNMPClient
from core.database_manager import DatabaseManager
from core.alarm_manager import AlarmManager
from core.port_change_detector import PortChangeDetector
from vendors.factory import VendorFactory
from vendors.base import PortInfo, DeviceInfo
from models.database import DeviceStatus, PortStatus, SNMPDevice
from utils.logger import DeviceLoggerAdapter

_DB_DEADLOCK_RETRIES: int = 3
_DB_DEADLOCK_RETRY_DELAY: float = 0.5  # seconds; doubles each attempt
_DB_DEADLOCK_JITTER_MAX: float = 0.3   # max random jitter added to each retry delay
_MYSQL_DEADLOCK_CODE: int = 1213       # MySQL deadlock error code
_MSSQL_DEADLOCK_CODE: int = 1205       # SQL Server deadlock error code
_MSSQL_DEADLOCK_SQLSTATE: str = '40001'  # SQLSTATE for serialization failure (deadlock)
# OID constants used directly in the polling engine
_OID_DOT1Q_PVID = '1.3.6.1.2.1.17.7.1.4.5.1.1'  # dot1qPvid (ifIndex → VLAN ID)
# Maximum number of OIDs to bundle into a single multi-varbind GET PDU when
# fetching individual port OIDs (e.g. CBS350 pethPsePortTable per-port GETs).
# Batching reduces round-trips and SNMP agent CPU load dramatically:
#   CBS350-48FP-4X: 96 OIDs → ~10 PDUs (was 96 sequential single-OID GETs).
# Value of 10 keeps each PDU well within the standard 1472-byte UDP MTU and is
# safe across all CBS350 firmware versions.
_INDIVIDUAL_OID_CHUNK_SIZE: int = 10


def _is_deadlock_error(exc: Exception) -> bool:
    """Return True if *exc* is a database deadlock error (MySQL 1213 or SQL Server 1205/40001)."""
    # SQLAlchemy wraps driver errors; check orig attribute first.
    orig = getattr(exc, 'orig', None)
    if orig is not None:
        args = getattr(orig, 'args', ())
        if args:
            # MySQL deadlock: error code 1213
            if args[0] == _MYSQL_DEADLOCK_CODE:
                return True
            # SQL Server deadlock via pyodbc: args = (sqlstate, message)
            # e.g. ('40001', '[40001] ... (1205) ...')
            if args[0] == _MSSQL_DEADLOCK_SQLSTATE:
                return True
            if len(args) > 1 and str(_MSSQL_DEADLOCK_CODE) in str(args[1]):
                return True
    # Fall back to case-insensitive string match for other driver wrappers.
    exc_str = str(exc)
    return (
        str(_MYSQL_DEADLOCK_CODE) in exc_str
        or str(_MSSQL_DEADLOCK_CODE) in exc_str
        or _MSSQL_DEADLOCK_SQLSTATE in exc_str
        or 'deadlock' in exc_str.lower()
    )


class DevicePoller:
    """Polls a single device and collects SNMP data."""
    
    def __init__(
        self,
        device_config: DeviceConfig,
        snmp_config: Any,
        db_manager: DatabaseManager,
        alarm_manager: AlarmManager,
        change_detector: PortChangeDetector,
        polling_data_interval: int = 60,
        mac_poll_interval: int = 60,
        device_info_poll_interval: int = 60,
        port_poll_interval: int = 15,
    ):
        """
        Initialize device poller.
        
        Args:
            device_config: Device configuration
            snmp_config: SNMP configuration
            db_manager: Database manager
            alarm_manager: Alarm manager
            change_detector: Port change detector
            polling_data_interval: Minimum seconds between device_polling_data
                INSERT rows for this device.  0 = insert every poll (old
                behaviour).  Status transitions (success↔failure) always force
                an immediate INSERT regardless of this interval.
            mac_poll_interval: Minimum seconds between MAC address table SNMP
                walks.  0 = walk every poll.  Cached MACs are used on
                intermediate cycles; the cache is cleared on port status changes
                so a fresh walk happens when a port comes back up.
            device_info_poll_interval: Minimum seconds between device-info
                SNMP collections (sysDescr, temp, fan, PoE, CPU).  0 = collect
                every poll.  Cached DeviceInfo is passed to update_device_status
                on intermediate cycles.
            port_poll_interval: Minimum seconds between port-status SNMP walks
                (ifTable, ifOperStatus, ifAdminStatus, dot1qPvid).  0 = walk
                every poll.  On cached cycles the DB port write and alarm checks
                are skipped entirely; alarm detection latency equals at most
                port_poll_interval seconds.  Default: 15 s (every cycle).
        """
        self.device_config = device_config
        self.snmp_config = snmp_config
        self.db_manager = db_manager
        self.alarm_manager = alarm_manager
        self.change_detector = change_detector
        self.polling_data_interval = polling_data_interval
        self.mac_poll_interval = mac_poll_interval
        self.device_info_poll_interval = device_info_poll_interval
        self.port_poll_interval = port_poll_interval
        
        # Per-device state for polling_data sampling.
        # _polling_data_last_write: timestamp of last device_polling_data INSERT.
        # _polling_data_last_success: last known success value (None = unknown).
        self._polling_data_last_write: Optional[datetime] = None
        self._polling_data_last_success: Optional[bool] = None
        
        # Per-device MAC table cache.
        # _mac_last_poll: timestamp of the last MAC walk (None = never polled).
        # _mac_cache: last MAC table result (port → [mac, …]).
        self._mac_last_poll: Optional[datetime] = None
        self._mac_cache: Dict[int, List[str]] = {}

        # Per-device DeviceInfo cache.
        # _device_info_last_poll: timestamp of the last device-info collection.
        # _device_info_cache: last DeviceInfo result (None = never polled).
        self._device_info_last_poll: Optional[datetime] = None
        self._device_info_cache: Optional[Any] = None  # DeviceInfo | None

        # Per-device port-status cache.
        # _port_last_poll: timestamp of the last port SNMP walk (None = never).
        # _port_cache: last port list from _poll_ports() ([] = never polled).
        # ports_fresh flag in poll() result indicates whether the cached or live
        # data was used this cycle; save_to_database uses it to skip stale writes.
        self._port_last_poll: Optional[datetime] = None
        self._port_cache: List[Any] = []
        
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
                'auth_password': v3_config.get('auth_password', ''),
                'priv_protocol': v3_config.get('priv_protocol', 'AES'),
                'priv_password': v3_config.get('priv_password', ''),
                # Use configured engine_id for devices that require it (e.g. CBS350).
                # Pass '' to let pysnmp auto-discover when not configured.
                'engine_id': v3_config.get('engine_id', '') or ''
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
        
        # The SNMP engine is intentionally NOT reset between poll cycles.
        #
        # Background: pysnmp SNMPv3 requires an "engine-discovery" handshake the
        # first time it contacts a remote device.  This involves two extra
        # UDP round-trips (probe → report → authed request) which add ~2-4 s
        # for each fresh SnmpEngine instance.
        #
        # Previous implementation created a new SnmpEngine once per cycle
        # (reset_engine()) to share it across all intra-cycle SNMP calls.
        # That cut the overhead from "3 s per call" to "3 s per cycle".
        #
        # Current implementation keeps the same SnmpEngine alive across cycles.
        # This means the discovery is paid ONLY ONCE per DevicePoller lifetime
        # (first poll after service start).  All subsequent polls skip discovery
        # entirely (~200 ms per request instead of ~3 s for the first request).
        #
        # Safety:
        #   • Remote engine-ID drift (device reboot): pysnmp detects the mismatch
        #     via a "wrongEngineID" report PDU and automatically re-discovers.
        #     One extra round-trip (~400 ms penalty, infrequent).
        #   • Memory: each client contacts exactly one peer; the cache is bounded.
        #   • Thread safety: each DevicePoller has its own SNMPClient/_engine.
        #
        # Net saving per device per cycle:  ~3 s (after the first poll).
        # Net saving for Faz 1 (38 parallel pollers): ~3 s off the critical path.

        try:
            # Test connection
            self.logger.debug("Starting poll")
            if not self.snmp_client.test_connection():
                result['error'] = "Device unreachable"
                self.logger.error("Device unreachable")
                # On transition to UNREACHABLE, clear caches so next successful
                # poll always fetches fresh device-info, port, and MAC data.
                self._device_info_cache = None
                self._device_info_last_poll = None
                self._mac_cache = {}
                self._mac_last_poll = None
                self._port_cache = []
                self._port_last_poll = None
                return result

            # ── Device info (rate-limited) ───────────────────────────────────
            # Poll only when the interval has elapsed OR we have no cached data.
            # On intermediate cycles the cached DeviceInfo is passed to the DB
            # so snmp_devices still receives near-current temperature, fan, etc.
            _now = datetime.utcnow()
            _device_info_elapsed = (
                self._device_info_last_poll is None
                or (_now - self._device_info_last_poll).total_seconds()
                   >= self.device_info_poll_interval
            )
            _should_poll_device_info = (
                self.device_info_poll_interval == 0
                or _device_info_elapsed
            )
            if _should_poll_device_info:
                device_info = self._poll_device_info()
                if device_info is not None:
                    self._device_info_cache = device_info
                    self._device_info_last_poll = datetime.utcnow()
                else:
                    # Poll returned None (e.g. env OID error) — keep old cache
                    device_info = self._device_info_cache
            else:
                device_info = self._device_info_cache
            result['device_info'] = device_info

            # ── Port status (rate-limited) ────────────────────────────────────
            # Walk ifTable / ifOperStatus / dot1qPvid only when the interval has
            # elapsed.  On intermediate cycles the cached port list is returned
            # and the 'ports_fresh' flag is set to False so save_to_database can
            # skip the DB write and alarm check for this cycle.
            #
            # SNMP yük notu (açıklama):
            # ─────────────────────────────────────────────────────────────────
            # SNMP polling her NMS sisteminde (SolarWinds, PRTG, Zabbix, vb.)
            # aynı şekilde çalışır: yönetim sunucusu switch'e UDP paketleri
            # gönderir, switch SNMP agent'ı bu paketleri kendi CPU'sunda işler
            # ve yanıtlar.  Yük miktarı şuna bağlıdır:
            #   1. Sorgu sıklığı  : Her 15 s → daha fazla UDP, daha fazla CPU
            #   2. OID derinliği  : GETBULK (ifTable, FDB walk) daha ağır,
            #                       scalar GET (sysDescr) çok hafif
            #   3. Paralel cihaz  : Tek switch'e tek kaynak sorgusu, ancak
            #                       tüm switch'ler aynı anda başlatılır
            #      (snmp_stagger_ms ile yayılır)
            #
            # Bizim yapımızda:
            #   • C9200/C9300 (IOS-XE): MAC walk için her VLAN için ayrı
            #     SNMPv3 context sorgusu gerekir — bu Cisco IOS-XE mimarisinin
            #     doğasıdır, tüm IOS-XE NMS entegrasyonları böyle çalışır.
            #   • CBS350: tek Q-BRIDGE FDB walk — daha verimli, ancak yine de
            #     birkaç yüz satır döndürebilir.
            #   • port_poll_interval=60 s: ifTable walk her 60 s'de bir →
            #     her cihaz için 3/4 döngüde SNMP ifTable isteği YOK.
            # ─────────────────────────────────────────────────────────────────
            _port_elapsed = (
                self._port_last_poll is None
                or (_now - self._port_last_poll).total_seconds()
                   >= self.port_poll_interval
            )
            _should_poll_ports = (
                self.port_poll_interval == 0
                or _port_elapsed
            )
            if _should_poll_ports:
                ports = self._poll_ports()
                self._port_cache = ports
                self._port_last_poll = datetime.utcnow()
                result['ports_fresh'] = True
            else:
                ports = self._port_cache
                result['ports_fresh'] = False
            result['ports'] = ports
            
            # ── MAC table (rate-limited) ─────────────────────────────────────
            # Walk the MAC FDB only when the interval has elapsed.  Between
            # walks the cached MAC table is used so port_status_data retains
            # the last-known mac_address / mac_addresses without an SNMP round-
            # trip.  This eliminates per-VLAN context walks on C9200 and the
            # FDB walk on CBS350 for 3 out of 4 cycles at 15 s poll interval.
            _mac_elapsed = (
                self._mac_last_poll is None
                or (_now - self._mac_last_poll).total_seconds()
                   >= self.mac_poll_interval
            )
            _should_poll_mac = (
                self.mac_poll_interval == 0
                or _mac_elapsed
            )
            if _should_poll_mac:
                mac_table = self._poll_mac_table()
                self._mac_cache = mac_table
                self._mac_last_poll = datetime.utcnow()
            else:
                mac_table = self._mac_cache

            # Associate MACs with ports
            self._associate_macs_with_ports(result['ports'], mac_table)

            # Apply VLAN corrections discovered via per-VLAN context MAC walks.
            # On C9200L / C9300L IOS-XE, dot1qPvid returns 0/1 for all access
            # ports.  collect_mac_with_vlan_contexts() updates _port_vlan_map
            # with the real VLANs (e.g. 70) after querying vlan-N SNMP contexts.
            if hasattr(self.vendor_mapper, '_port_vlan_map') and self.vendor_mapper._port_vlan_map:
                for port in result['ports']:
                    discovered = self.vendor_mapper._port_vlan_map.get(port.port_number)
                    if discovered and discovered > 1:
                        port.vlan_id = discovered

            result['success'] = True
            duration_s = (time.time() - start_time)
            self.logger.debug(f"Poll successful: {len(result['ports'])} ports collected ({duration_s:.1f}s)")
            if duration_s > 15:
                self.logger.warning(
                    f"Yavaş SNMP sorgu [{self.device_config.name}]: {duration_s:.1f}s "
                    f"(port sayısı: {len(result['ports'])})"
                )
        
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

            # Walk any extra OIDs the mapper requests for device info.
            # Vendor mappers whose environmental sensor indices vary (e.g. CBS350
            # temperature/fan table where index .1 may not exist) can override
            # get_device_info_walk_oids() to return parent table OIDs.  Each is
            # walked here and the results are merged into snmp_data so that
            # parse_device_info() can find values at any index (not just .1).
            if hasattr(self.vendor_mapper, 'get_device_info_walk_oids'):
                for walk_oid in self.vendor_mapper.get_device_info_walk_oids():
                    walked = self.snmp_client.get_bulk(walk_oid, 10)
                    for oid_str, val in walked:
                        snmp_data[oid_str] = val

            device_info = self.vendor_mapper.parse_device_info(snmp_data)
            return device_info
        except Exception as e:
            self.logger.error(f"Failed to poll device info: {e}")
            return None
    
    def _poll_ports(self) -> List[PortInfo]:
        """Poll port information."""
        try:
            # ── Determine whether the mapper supports limited-index column walks ──
            # CBS350 in stack mode has 4× more ifTable rows than needed.
            # get_if_column_oids() returns individual column OIDs to walk;
            # get_max_port_ifindex() returns the highest unit-1 ifIndex so that
            # SNMPClient.get_bulk() can stop early and skip phantom rows.
            max_ifindex: int = 0
            if_col_oids: List[str] = []
            if hasattr(self.vendor_mapper, 'get_if_column_oids'):
                if_col_oids = self.vendor_mapper.get_if_column_oids()
            if if_col_oids and hasattr(self.vendor_mapper, 'get_max_port_ifindex'):
                max_ifindex = self.vendor_mapper.get_max_port_ifindex()

            snmp_data = {}

            # Walk individual interface column OIDs with early stop (CBS350 fast path).
            for oid_col in if_col_oids:
                results = self.snmp_client.get_bulk(
                    oid_col,
                    self.snmp_config.max_bulk_size,
                    stop_at_index=max_ifindex,
                )
                for oid, value in results:
                    snmp_data[oid] = value

            # Walk remaining OIDs (Q-BRIDGE VLAN, or full parent tables as fallback).
            oid_prefixes = self.vendor_mapper.get_port_info_oids()
            for oid_prefix in oid_prefixes:
                results = self.snmp_client.get_bulk(oid_prefix, self.snmp_config.max_bulk_size)
                for oid, value in results:
                    snmp_data[oid] = value

            # Fetch individual OIDs in batches to reduce SNMP round-trips and
            # agent CPU load.  Previously each OID was fetched with a separate
            # single-varbind GET call; for CBS350-48FP-4X this meant 96 sequential
            # GET requests for pethPsePortTable (PoE detect + class per port),
            # which overwhelmed the CBS350 SNMP agent and caused subsequent
            # GETBULK calls (MAC table, Q-BRIDGE) to time out.
            # Batching _INDIVIDUAL_OID_CHUNK_SIZE OIDs per PDU reduces the round-
            # trip count from ~96 to ~10 while staying well within PDU size limits.
            # get_multiple() already filters noSuchInstance/noSuchObject responses
            # so SFP+ uplink ports that return noSuchInstance are silently skipped.
            individual_oids = self.vendor_mapper.get_port_get_oids()
            for chunk_start in range(0, len(individual_oids), _INDIVIDUAL_OID_CHUNK_SIZE):
                chunk = individual_oids[chunk_start:chunk_start + _INDIVIDUAL_OID_CHUNK_SIZE]
                chunk_results = self.snmp_client.get_multiple(chunk)
                snmp_data.update(chunk_results)

            # Parse port info
            ports = self.vendor_mapper.parse_port_info(snmp_data)
            return ports
        except Exception as e:
            self.logger.error(f"Failed to poll ports: {e}")
            return []
    
    def _poll_mac_table(self) -> Dict[int, List[str]]:
        """Poll MAC address table.

        Uses a two-phase approach for mappers that expose ``get_mac_fallback_oids()``:
          Phase 1 – walk only the primary (preferred) OIDs from ``get_mac_table_oids()``.
          Check if the Q-BRIDGE OID produced any data (i.e., the switch supports
          the Q-BRIDGE MIB, which all CBS350 firmware versions do).
          If yes  → parse and return immediately (saves 1-3 s per cycle by
                     skipping the redundant ``dot1dTpFdb`` walk).
          If no   → walk the fallback OIDs from ``get_mac_fallback_oids()`` and
                     parse the combined data set (backward-compatible fallback
                     for very old firmware or unsupported switches).
        """
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

            # ── Phase 1: primary MAC OIDs (Q-BRIDGE FDB + bridge-port map) ──
            oid_prefixes = self.vendor_mapper.get_mac_table_oids()
            snmp_data: Dict[str, Any] = {}
            for oid_prefix in oid_prefixes:
                results = self.snmp_client.get_bulk(oid_prefix, self.snmp_config.max_bulk_size)
                for oid, value in results:
                    snmp_data[oid] = value

            # ── Phase 2 (conditional): fallback OIDs only if Q-BRIDGE was empty ──
            # For CBS350, the Q-BRIDGE OID (OID_DOT1Q_FDB_PORT) is present in
            # snmp_data when the switch has learned MAC entries.  If that OID
            # returned no rows (e.g. very old firmware), walk the plain dot1dTpFdb
            # as a fallback.  This avoids the redundant walk in the common case.
            if hasattr(self.vendor_mapper, 'get_mac_fallback_oids'):
                q_bridge_oid = getattr(self.vendor_mapper, 'OID_DOT1Q_FDB_PORT', None)
                q_bridge_has_data = q_bridge_oid and any(
                    oid.startswith(q_bridge_oid + '.') for oid in snmp_data
                )
                if not q_bridge_has_data:
                    self.logger.debug(
                        "Q-BRIDGE MAC walk empty; walking plain dot1d FDB as fallback"
                    )
                    for oid_prefix in self.vendor_mapper.get_mac_fallback_oids():
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
        exclude = set(self.device_config.mac_exclude_ports)
        for port in ports:
            if port.port_number in exclude:
                continue
            if port.port_number in mac_table:
                macs = mac_table[port.port_number]
                if macs:
                    port.mac_address = macs[0]
                    # Store all MACs for later use if needed
                    if not hasattr(port, '_all_macs'):
                        port._all_macs = macs
    
    def save_to_database(self, poll_result: Dict[str, Any]) -> None:
        """
        Save poll results to database.
        
        Args:
            poll_result: Poll results dictionary
        """
        _t0 = time.perf_counter()
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
                    # Store engine_id so the PHP front-end uses the same value as the
                    # Python worker for SNMPv3 contextEngineID (e.g. CBS350 requires
                    # an explicit engine_id; without it PHP falls back to auto-discovery
                    # which may fail and cause port detail / health bar to show stale DB data).
                    snmp_engine_id=v3.get('engine_id', '') or '',
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
                    total_ports=device_info.total_ports if device_info else None,
                    fan_status=device_info.fan_status if device_info else None,
                    temperature_c=device_info.temperature_c if device_info else None,
                    poe_nominal_w=device_info.poe_nominal_w if device_info else None,
                    poe_consumed_w=device_info.poe_consumed_w if device_info else None,
                    cpu_1min=device_info.cpu_1min if device_info else None,
                )
                
                # Check device reachability alarm
                self.alarm_manager.check_device_reachability(session, device, True)

                # Check environmental alarms (temperature, fan, CPU)
                if device_info:
                    self.alarm_manager.check_temperature(
                        session, device, device_info.temperature_c
                    )
                    self.alarm_manager.check_fan_status(
                        session, device, device_info.fan_status
                    )
                    self.alarm_manager.check_cpu_usage(
                        session, device, device_info.cpu_1min
                    )
            else:
                self.db_manager.update_device_status(
                    session,
                    device,
                    DeviceStatus.UNREACHABLE if poll_result.get('error') == 'Device unreachable' else DeviceStatus.ERROR
                )
                
                # Check device reachability alarm
                self.alarm_manager.check_device_reachability(session, device, False)
            
            # Save polling data — rate-limited to reduce device_polling_data growth.
            # Rules (evaluated in priority order):
            #   1. Always write when polling_data_interval == 0 (no sampling).
            #   2. Always write on a success↔failure status TRANSITION so alarm
            #      history and the "device went down at HH:MM" information is never
            #      lost even when sampling is active.
            #   3. Write when polling_data_interval seconds have elapsed since the
            #      last insert for this device.
            _current_success = poll_result['success']
            _status_changed = (
                self._polling_data_last_success is not None
                and _current_success != self._polling_data_last_success
            )
            _interval_elapsed = (
                self._polling_data_last_write is None
                or (datetime.utcnow() - self._polling_data_last_write).total_seconds()
                   >= self.polling_data_interval
            )
            _should_write = (
                self.polling_data_interval == 0
                or _status_changed
                or _interval_elapsed
            )
            if _should_write:
                _di = poll_result.get('device_info')
                self.db_manager.save_polling_data(
                    session,
                    device,
                    success=_current_success,
                    poll_duration_ms=poll_result['duration_ms'],
                    error_message=poll_result.get('error'),
                    system_name=(_di.system_name if _di and _di.system_name not in (None, '', 'Unknown') else None),
                    system_description=(_di.system_description if _di and _di.system_description not in (None, '', 'Unknown') else None),
                    system_uptime=(_di.system_uptime if _di and _di.system_uptime else None),
                    temperature=(_di.temperature_c if _di and _di.temperature_c is not None else None),
                    cpu_usage=_di.cpu_1min if _di else None,
                    memory_usage=_di.memory_usage if _di else None,
                )
                self._polling_data_last_write = datetime.utcnow()
            self._polling_data_last_success = _current_success
            
            # Save port data
            # ─────────────────────────────────────────────────────────────────
            # IMPORTANT: wrap the entire port processing loop in no_autoflush.
            # SQLAlchemy fires an automatic flush before every SELECT query when
            # there are pending dirty objects (e.g. mac_tracking.last_seen was
            # updated earlier in this loop).  That premature flush runs a DB
            # UPDATE concurrently with identical UPDATEs from other parallel
            # workers → MySQL deadlock (error 1213).
            #
            # With no_autoflush, all pending changes accumulate in memory and
            # are written only at session.commit() (end of session_scope).
            # If a deadlock occurs at commit time, _save_one retries the whole
            # device without the exponential pile-up seen in mid-loop retries.
            # ─────────────────────────────────────────────────────────────────
            if poll_result['success']:
                # Skip port DB write and alarm check when port data is not fresh
                # (port_poll_interval cache is active).  Stale data from the cache
                # would cause redundant DB UPDATEs and would NOT reflect actual port
                # state changes — the alarm detection relies on state TRANSITIONS
                # which are only visible in fresh SNMP data.
                _ports_fresh = poll_result.get('ports_fresh', True)
                if not _ports_fresh:
                    return
                with session.no_autoflush:
                    for port in poll_result['ports']:
                        # Convert status strings to enums.
                        # Preserve the vendor's reported status: map 'up' → UP,
                        # 'down' → DOWN, everything else (e.g. 'unknown', 'dormant',
                        # 'notPresent') → UNKNOWN so we don't falsely record a port
                        # as DOWN just because its SNMP OID was absent during the walk.
                        # NOTE: admin_status DB ENUM is ('up','down','testing') — no 'unknown'.
                        # For admin_status, fall back to DOWN for any non-up value because
                        # 'testing' and other non-up admin states mean the port is
                        # administratively disabled/non-forwarding — operationally equivalent
                        # to DOWN from a monitoring perspective.
                        # 'lowerLayerDown' (ifOperStatus=7) explicitly means the port is
                        # down because a lower-layer interface is down — treat as DOWN, not
                        # UNKNOWN.  CBS350 commonly reports this for disconnected access ports.
                        _status_map = {
                            'up': PortStatus.UP,
                            'down': PortStatus.DOWN,
                            'lowerLayerDown': PortStatus.DOWN,
                        }
                        admin_status = _status_map.get(port.admin_status, PortStatus.DOWN)
                        oper_status  = _status_map.get(port.oper_status,  PortStatus.UNKNOWN)
                        
                        # Save port status
                        all_macs = getattr(port, '_all_macs', None)
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
                            mac_addresses=json.dumps(all_macs) if all_macs and len(all_macs) > 1 else None,
                            vlan_id=port.vlan_id,
                            in_octets=port.in_octets,
                            out_octets=port.out_octets,
                            in_errors=port.in_errors,
                            out_errors=port.out_errors,
                            in_discards=port.in_discards,
                            out_discards=port.out_discards,
                            poe_detecting=port.poe_detecting,
                            poe_power_mw=port.poe_power_mw,
                            poe_class=port.poe_class,
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
                            if _is_deadlock_error(e):
                                # Re-raise deadlock so _save_one can retry the whole device
                                raise
                            self.logger.error(f"Error detecting changes on port {port.port_number}: {e}")
                        
                        # Check for port status alarms
                        self.alarm_manager.check_port_status(
                            session,
                            device,
                            port.port_number,
                            port.port_name,
                            admin_status,
                            oper_status,
                            vlan_id=port.vlan_id,
                            port_alias=port.port_alias
                        )
                # Flush batched last_seen updates for this device in one query.
                # Must be inside no_autoflush so the raw UPDATE doesn't race with
                # any pending ORM dirty objects before they are committed together.
                try:
                    self.change_detector.flush_last_seen_batch(session)
                except Exception as e:
                    self.logger.warning(f"flush_last_seen_batch error [{self.device_config.name}]: {e}")
        _elapsed = time.perf_counter() - _t0
        self.logger.debug(
            f"save_to_database [{self.device_config.name}]: {_elapsed:.2f}s "
            f"({len(poll_result.get('ports', []))} ports)"
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
                    self.change_detector,
                    polling_data_interval=config.polling.polling_data_interval,
                    mac_poll_interval=config.polling.mac_poll_interval,
                    device_info_poll_interval=config.polling.device_info_poll_interval,
                    port_poll_interval=config.polling.port_poll_interval,
                )
                self.pollers.append(poller)
        
        self.logger.info(f"Polling engine initialized with {len(self.pollers)} devices")
    
    def collect_all(self) -> List[Tuple[DevicePoller, Dict[str, Any]]]:
        """
        FAZ 1 – Sadece SNMP veri toplama (ağ I/O).

        Tüm switch'ler paralel olarak sorgulanır.  Bu faz yalnızca ağ
        trafiğinden oluşur; veritabanı yazma veya alarm tespiti **yoktur**.
        ``snmp_stagger_ms`` > 0 ise thread'ler arasına küçük bir gecikme
        eklenir; bu, anlık CPU/ağ yük patlamasını yayarak tepe kullanımını
        düşürür.  0 ise tüm cihazlar aynı anda başlatılır.

        Returns:
            List of (DevicePoller, raw_result) tuples – işleme hazır ham veri.
        """
        if not self.pollers:
            self.logger.warning("No enabled devices to poll")
            return []

        self.logger.debug(f"Faz 1 – SNMP toplama başlıyor: {len(self.pollers)} cihaz")
        _faz1_start = time.perf_counter()

        paired: List[tuple] = []  # (poller, result)

        stagger_s = max(0.0, self.config.polling.snmp_stagger_ms / 1000.0)
        with ThreadPoolExecutor(max_workers=self.config.polling.max_workers) as executor:
            # SNMP sorguları başlatılır.  snmp_stagger_ms > 0 ise her cihaz
            # arasında küçük bir bekleme eklenir; bu, anlık CPU ve ağ yük
            # patlamasını (burst) yayarak tepe kullanımı düşürür.
            # snmp_stagger_ms = 0 ise eski davranış korunur (tüm cihazlar
            # aynı anda başlatılır).  Son cihazdan sonra bekleme yapılmaz.
            future_to_poller: Dict[Future, DevicePoller] = {}
            last_idx = len(self.pollers) - 1
            for i, poller in enumerate(self.pollers):
                future_to_poller[executor.submit(poller.poll)] = poller
                if stagger_s > 0 and i < last_idx:
                    time.sleep(stagger_s)

            for future in as_completed(future_to_poller):
                poller = future_to_poller[future]
                try:
                    result = future.result()
                    paired.append((poller, result))
                except Exception as e:
                    self.logger.error(
                        f"SNMP toplama hatası [{poller.device_config.name}]: {e}"
                    )
                    paired.append((poller, {
                        'device_name': poller.device_config.name,
                        'device_ip': poller.device_config.ip,
                        'success': False,
                        'error': str(e),
                        'duration_ms': 0,
                        'device_info': None,
                        'ports': [],
                    }))

        successful = sum(1 for _, r in paired if r.get('success'))
        _faz1_elapsed = time.perf_counter() - _faz1_start
        self.logger.debug(
            f"Faz 1 tamamlandı: {successful}/{len(paired)} cihaz başarılı "
            f"({_faz1_elapsed:.1f}s)"
        )
        return paired

    def process_results(self, paired: List[Tuple[DevicePoller, Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        FAZ 2 – Veritabanı yazma ve alarm işleme (CPU/DB işi).

        Ham SNMP sonuçları **paralel** olarak veritabanına yazılır; her cihaz
        kendi DB oturumunu (session) açar.  Paralel işçi sayısı ``db_max_workers``
        config değeriyle doğrudan kontrol edilebilir; 0 ise otomatik hesaplanır
        (max_workers // 2, en az 4).  Düşük bir değer Phase 2 CPU tepesini
        azaltır; yüksek bir değer DB yazmasını hızlandırır.

        Args:
            paired: collect_all() tarafından döndürülen (DevicePoller, result_dict)
                    çiftlerinin listesi.

        Returns:
            List of raw result dicts (geriye dönük uyumluluk için).
        """
        if not paired:
            return []

        self.logger.debug(f"Faz 2 – DB/alarm işleme başlıyor: {len(paired)} sonuç (paralel)")
        _faz2_start = time.perf_counter()
        _deadlock_total = 0

        # DB işçi sayısı: db_max_workers > 0 ise config'den al;
        # aksi hâlde max_workers'ın yarısını kullan (en az 4, en fazla 16).
        _cfg_db = self.config.polling.db_max_workers
        db_workers = _cfg_db if _cfg_db > 0 else max(4, min(16, self.config.polling.max_workers // 2))

        # Pre-populate with the raw result dicts so the list is never None even
        # if a worker raises unexpectedly.
        results: List[Dict[str, Any]] = [r for _, r in paired]

        def _save_one(idx_poller_result):
            nonlocal _deadlock_total
            idx, poller, result = idx_poller_result
            _t_dev = time.perf_counter()
            for attempt in range(_DB_DEADLOCK_RETRIES + 1):
                try:
                    poller.save_to_database(result)
                    break
                except Exception as e:
                    if _is_deadlock_error(e) and attempt < _DB_DEADLOCK_RETRIES:
                        _deadlock_total += 1
                        # Jitter: delay = base * 2^attempt + small random offset
                        # so workers don't all retry at the exact same instant.
                        delay = _DB_DEADLOCK_RETRY_DELAY * (2 ** attempt) + random.uniform(0, _DB_DEADLOCK_JITTER_MAX)
                        self.logger.warning(
                            f"Deadlock [{poller.device_config.name}] "
                            f"deneme {attempt + 1}/{_DB_DEADLOCK_RETRIES}, "
                            f"{delay:.2f}s sonra tekrar deneniyor"
                        )
                        time.sleep(delay)
                    else:
                        self.logger.error(
                            f"DB kayıt hatası [{poller.device_config.name}]: {e}"
                        )
                        break
            _dev_elapsed = time.perf_counter() - _t_dev
            if _dev_elapsed > 5.0:
                self.logger.warning(
                    f"Yavaş DB işlemi [{poller.device_config.name}]: {_dev_elapsed:.1f}s"
                )
            return idx, result

        tasks = [(i, p, r) for i, (p, r) in enumerate(paired)]

        with ThreadPoolExecutor(max_workers=db_workers) as executor:
            futures = {executor.submit(_save_one, t): t for t in tasks}
            for future in as_completed(futures):
                try:
                    idx, result = future.result()
                    results[idx] = result
                except Exception as e:
                    task = futures[future]
                    idx, poller, raw_result = task
                    results[idx] = raw_result
                    self.logger.error(
                        f"Faz 2 işçi hatası [{poller.device_config.name}]: {e}"
                    )

        successful = sum(1 for r in results if r and r.get('success'))
        _faz2_elapsed = time.perf_counter() - _faz2_start
        _deadlock_msg = f", deadlock={_deadlock_total}" if _deadlock_total > 0 else ""
        self.logger.debug(
            f"Faz 2 tamamlandı: {successful}/{len(results)} cihaz işlendi "
            f"({_faz2_elapsed:.1f}s, {db_workers} paralel işçi{_deadlock_msg})"
        )
        return results

    def poll_all_devices(self) -> List[Dict[str, Any]]:
        """
        Geriye dönük uyumluluk sarmalayıcısı.

        collect_all() + process_results() çiftini art arda çağırır.
        Yeni kod doğrudan iki fazı ayrı ayrı çağırabilir; bu metot eski
        çağrıların bozulmaması için korunmaktadır.
        """
        paired = self.collect_all()
        return self.process_results(paired)