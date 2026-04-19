"""
SNMP Client for querying network devices.
Supports both SNMP v2c and v3.

NOTE: This module uses pysnmp-lextudio, which is a maintained fork of pysnmp
that supports Python 3.12+. The API is compatible with the original pysnmp.
"""

from typing import Optional, Dict, List, Tuple, Any
import logging

# SNMP imports - wrapped in try/except for graceful degradation
# Using explicit imports for pysnmp-lextudio 5.x compatibility
try:
    from pysnmp.hlapi import (
        UsmUserData, CommunityData,
        usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
        usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
        usmAesCfb128Protocol, usmAesCfb192Protocol, usmAesCfb256Protocol,
        usmDESPrivProtocol,
        SnmpEngine, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd, bulkCmd,
        nextCmd
    )
    from pysnmp.proto.rfc1902 import OctetString as SnmpOctetString
    SNMP_AVAILABLE = True
except ImportError as e:
    SNMP_AVAILABLE = False
    import_error = str(e)
    logging.warning(f"pysnmp not available - SNMP functionality will be limited. Error: {import_error}")
    logging.warning("To fix: pip install pysnmp-lextudio")
except Exception as e:
    SNMP_AVAILABLE = False
    import_error = str(e)
    logging.error(f"Unexpected error importing pysnmp: {import_error}")
    logging.error("To fix: pip install --force-reinstall pysnmp-lextudio")


def _oid_to_str(name) -> str:
    """
    Convert a pysnmp OID object to a dotted numeric string.
    With lookupMib=False on all SNMP calls, pysnmp never resolves OIDs to
    symbolic MIB names, so str(name) always returns dotted numeric notation
    e.g. '1.3.6.1.2.1.17.7.1.4.2.1.5.0.50'.
    """
    return str(name)


class SNMPClient:
    """
    SNMP client wrapper for pysnmp.
    Provides simplified interface for SNMP operations.
    """
    
    def __init__(
        self,
        host: str,
        port: int = 161,
        version: str = "2c",
        community: str = "public",
        timeout: int = 2,  # Test script'te 2 saniye
        retries: int = 1,  # Test script'te 1 deneme
        username: Optional[str] = None,
        auth_protocol: Optional[str] = None,
        auth_password: Optional[str] = None,
        priv_protocol: Optional[str] = None,
        priv_password: Optional[str] = None,
        engine_id: Optional[str] = None
    ):
        """
        Initialize SNMP client.
        
        Args:
            host: Target device IP or hostname
            port: SNMP port (default 161)
            version: SNMP version ("2c" or "3")
            community: SNMP community string for v2c
            timeout: Timeout in seconds (default 2)
            retries: Number of retries (default 1)
            username: SNMPv3 username
            auth_protocol: SNMPv3 auth protocol (SHA or MD5)
            auth_password: SNMPv3 auth password
            priv_protocol: SNMPv3 privacy protocol (AES or DES)
            priv_password: SNMPv3 privacy password
            engine_id: SNMPv3 engine ID (hex string, optional)
        """
        self.host = host
        self.port = port
        self.version = version
        self.community = community
        self.timeout = timeout
        self.retries = retries
        
        # SNMPv3 parameters
        self.username = username
        self.auth_protocol = auth_protocol
        self.auth_password = auth_password
        self.priv_protocol = priv_protocol
        self.priv_password = priv_password
        self.engine_id = engine_id
        
        self.logger = logging.getLogger('snmp_worker.snmp_client')
        
        # Setup authentication data
        self._auth_data = self._setup_auth()
        
        # Setup transport target
        self._transport = UdpTransportTarget(
            (host, port),
            timeout=timeout,
            retries=retries
        )
        self._engine = SnmpEngine()
        self._context = ContextData()
    
    def _setup_auth(self):
        """Setup authentication data based on SNMP version."""
        if not SNMP_AVAILABLE:
            return None
            
        if self.version == "3":
            # ★★★ TEST SCRIPT'İ İLE %100 UYUMLU SNMPv3 AUTH ★★★
            
            # Auth Protocol Mapping
            auth_proto = usmHMACSHAAuthProtocol  # DEFAULT: SHA
            if self.auth_protocol:
                auth_proto_upper = self.auth_protocol.upper()
                if auth_proto_upper == "MD5":
                    auth_proto = usmHMACMD5AuthProtocol
                elif auth_proto_upper == "SHA224":
                    auth_proto = usmHMAC128SHA224AuthProtocol
                elif auth_proto_upper == "SHA256":
                    auth_proto = usmHMAC192SHA256AuthProtocol
                elif auth_proto_upper == "SHA384":
                    auth_proto = usmHMAC256SHA384AuthProtocol
                elif auth_proto_upper == "SHA512":
                    auth_proto = usmHMAC384SHA512AuthProtocol
                # SHA varsayılan, başka bir değişiklik yapma
            
            # Priv Protocol Mapping
            priv_proto = usmAesCfb128Protocol  # DEFAULT: AES128
            if self.priv_protocol:
                priv_proto_upper = self.priv_protocol.upper()
                if priv_proto_upper == "DES":
                    priv_proto = usmDESPrivProtocol
                elif priv_proto_upper in ["AES192", "AES-192"]:
                    priv_proto = usmAesCfb192Protocol
                elif priv_proto_upper in ["AES256", "AES-256"]:
                    priv_proto = usmAesCfb256Protocol
                # AES128 varsayılan
            
            # ★★★ CRITICAL FIX: Doğru parametre sırası - test script'i ile aynı ★★★
            # UsmUserData(userName, authKey, privKey, authProtocol, privProtocol)
            usm_kwargs = dict(
                authProtocol=auth_proto,
                privProtocol=priv_proto
            )
            # If an engine_id is configured (e.g. CBS350 requires explicit engine ID),
            # pass it as securityEngineId to skip USM auto-discovery.
            if self.engine_id:
                try:
                    import binascii
                    engine_bytes = binascii.unhexlify(self.engine_id)
                    usm_kwargs['securityEngineId'] = SnmpOctetString(engine_bytes)
                    self.logger.debug(f"Using explicit engine_id for {self.host}: {self.engine_id}")
                except Exception as e:
                    self.logger.warning(
                        f"Invalid engine_id '{self.engine_id}' for {self.host}: {e} "
                        f"(engine_id must be a valid hexadecimal string, e.g. '0102030405060708') "
                        f"— falling back to auto-discovery"
                    )
            return UsmUserData(
                self.username or 'snmpuser',
                self.auth_password or '',  # 2. parametre: authKey
                self.priv_password or '',  # 3. parametre: privKey
                **usm_kwargs
            )
        else:
            # SNMPv2c
            return CommunityData(self.community, mpModel=1)
    
    def get(self, oid: str) -> Optional[Tuple[str, Any]]:
        """
        Perform SNMP GET operation.
        
        Args:
            oid: OID to query
            
        Returns:
            Tuple of (oid, value) or None on error
        """
        if not SNMP_AVAILABLE:
            self.logger.error("SNMP library not available - cannot perform SNMP GET operation")
            self.logger.error("Install pysnmp with: pip install pysnmp-lextudio")
            return None
            
        try:
            iterator = getCmd(
                self._engine,
                self._auth_data,
                self._transport,
                self._context,
                ObjectType(ObjectIdentity(oid)),
                lookupMib=False
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication:
                self.logger.error(f"SNMP GET error: {errorIndication}")
                return None
            elif errorStatus:
                self.logger.error(f"SNMP GET error: {errorStatus.prettyPrint()}")
                return None
            else:
                for name, value in varBinds:
                    return _oid_to_str(name), value
        
        except Exception as e:
            self.logger.error(f"Exception during SNMP GET: {e}")
            return None
    
    def reset_engine(self) -> None:
        """Create a fresh SnmpEngine, discarding all cached peer state.

        **Normal operation**: This method is no longer called per-poll-cycle.
        The ``DevicePoller.poll()`` keeps the same engine alive across cycles so
        the SNMPv3 engine-ID discovery (~3 s) is paid only once (at service start).

        **When to call manually**:
        - After a persistent authentication/timeout failure where you want to
          force a clean re-discovery of the remote engine.
        - During unit-tests that need isolated engine state per test case.
        - If the operator rotates SNMP credentials and wants the new keys to
          take effect without restarting the service.

        Calling this method causes the next SNMP request on this client to pay
        the full SNMPv3 handshake overhead (~2-4 s) as a one-time cost.
        """
        self._engine = SnmpEngine()
        self._transport = UdpTransportTarget(
            (self.host, self.port),
            timeout=self.timeout,
            retries=self.retries
        )
        self._auth_data = self._setup_auth()
        self._context = ContextData()

    def get_bulk(self, oid: str, max_repetitions: int = 50,
                 stop_at_index: int = 0) -> List[Tuple[str, Any]]:
        """
        Perform SNMP GETBULK operation (walk).
        Falls back to GETNEXT walk if GETBULK returns empty results.

        Uses the shared self._engine / self._transport / self._auth_data that
        were set up by __init__ or the most recent reset_engine() call.
        Reusing the engine means the SNMPv3 engine-discovery handshake is
        performed only once per poll cycle (at the first GET/GETBULK call),
        and all subsequent calls within the same poll reuse the cached remote
        engine-ID.  This eliminates the ~3 s per-call overhead that was present
        when a fresh SnmpEngine() was created for every walk.

        Note: all calls use lookupMib=False so pysnmp never loads or caches
        MIB modules.  The OID objects returned in varBinds are always numeric
        dotted strings (e.g. '1.3.6.1.2.1.2.2.1.2.1'), making it safe to
        reuse the same engine across multiple OID subtrees.

        Args:
            oid: Starting OID
            max_repetitions: Maximum number of repetitions
            stop_at_index: When > 0, stop the walk as soon as the last OID
                component (the row index) exceeds this value.  Used to skip
                phantom stack-unit interfaces on CBS350 in stack mode: only
                unit-1 interfaces (ifIndex 1..N) are collected; phantom
                unit-2/3/4 interfaces (ifIndex N+1..4N) are silently dropped.
                Pass 0 (default) for a full subtree walk.

        Returns:
            List of (oid, value) tuples
        """
        results = []
        done = False

        try:
            iterator = bulkCmd(
                self._engine,
                self._auth_data,
                self._transport,
                self._context,
                0,  # nonRepeaters
                max_repetitions,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                lookupMib=False
            )

            for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                if errorIndication:
                    self.logger.error(f"SNMP GETBULK error: {errorIndication}")
                    break
                elif errorStatus:
                    self.logger.error(f"SNMP GETBULK error: {errorStatus.prettyPrint()}")
                    break
                else:
                    for name, value in varBinds:
                        oid_str = _oid_to_str(name)
                        # Skip SNMP error sentinels that indicate end-of-MIB or missing OID
                        v_str = str(value).strip()
                        if v_str in ('noSuchInstance', 'noSuchObject', 'endOfMibView'):
                            continue
                        if stop_at_index > 0:
                            try:
                                last = int(oid_str.rsplit('.', 1)[1])
                                if last > stop_at_index:
                                    done = True
                                    break
                            except (ValueError, IndexError):
                                pass
                        results.append((oid_str, value))
                    if done:
                        break

        except Exception as e:
            self.logger.error(f"Exception during SNMP GETBULK: {e}")

        # If GETBULK returned nothing, fall back to GETNEXT walk.
        # Some devices (e.g., CBS350) may not respond to GETBULK for certain OID subtrees.
        if not results:
            self.logger.debug(f"GETBULK empty for {oid}, falling back to GETNEXT walk")
            results = self._walk_getnext(oid, stop_at_index=stop_at_index)

        return results

    def _walk_getnext(self, oid: str,
                      stop_at_index: int = 0) -> List[Tuple[str, Any]]:
        """
        Walk an OID subtree using GETNEXT (nextCmd).
        Used as fallback when GETBULK returns no results.
        Reuses self._engine (same rationale as get_bulk).
        """
        results = []
        try:
            iterator = nextCmd(
                self._engine,
                self._auth_data,
                self._transport,
                self._context,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                lookupMib=False
            )
            for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                if errorIndication:
                    self.logger.debug(f"SNMP GETNEXT error: {errorIndication}")
                    break
                elif errorStatus:
                    self.logger.debug(f"SNMP GETNEXT error: {errorStatus.prettyPrint()}")
                    break
                else:
                    done = False
                    for name, value in varBinds:
                        oid_str = _oid_to_str(name)
                        # Skip SNMP error sentinels
                        v_str = str(value).strip()
                        if v_str in ('noSuchInstance', 'noSuchObject', 'endOfMibView'):
                            continue
                        if stop_at_index > 0:
                            try:
                                last = int(oid_str.rsplit('.', 1)[1])
                                if last > stop_at_index:
                                    done = True
                                    break
                            except (ValueError, IndexError):
                                pass
                        results.append((oid_str, value))
                    if done:
                        break
        except Exception as e:
            self.logger.debug(f"Exception during SNMP GETNEXT walk: {e}")
        return results

    def get_bulk_with_context(self, oid: str, context_name: str,
                              max_repetitions: int = 50) -> List[Tuple[str, Any]]:
        """Walk an OID subtree using a specific SNMPv3 context name.

        Required for Cisco IOS-XE (C9200L / C9300L) MAC table access:
        the dot1d Bridge FDB is per-VLAN and only reachable via the
        ``vlan-<id>`` SNMPv3 context.  The standard empty-context walk
        returns nothing for those tables.

        Reuses self._engine / self._transport / self._auth_data so that
        the SNMPv3 engine discovery is paid at most once per poll cycle
        (the remote engine-ID is cached after the first SNMP call).
        Only the ContextData changes per call.

        Args:
            oid: Starting OID prefix to walk.
            context_name: SNMPv3 context name, e.g. ``"vlan-1"`` or ``"vlan-130"``.
            max_repetitions: GETBULK max-repetitions value.

        Returns:
            List of (oid_string, value) tuples, or empty list on error.
        """
        if not SNMP_AVAILABLE:
            return []
        results: List[Tuple[str, Any]] = []
        ctx = ContextData(contextName=context_name.encode() if isinstance(context_name, str) else context_name)
        try:
            iterator = bulkCmd(
                self._engine,
                self._auth_data,
                self._transport,
                ctx,
                0,
                max_repetitions,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                lookupMib=False
            )
            for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                if errorIndication or errorStatus:
                    break
                for name, value in varBinds:
                    results.append((_oid_to_str(name), value))
        except Exception as e:
            self.logger.debug(f"SNMP GETBULK context '{context_name}' error: {e}")
        # Fall back to GETNEXT if GETBULK returned nothing
        if not results:
            try:
                iterator = nextCmd(
                    self._engine,
                    self._auth_data,
                    self._transport,
                    ctx,
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False,
                    lookupMib=False
                )
                for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                    if errorIndication or errorStatus:
                        break
                    for name, value in varBinds:
                        results.append((_oid_to_str(name), value))
            except Exception as e:
                self.logger.debug(f"SNMP GETNEXT context '{context_name}' error: {e}")
        return results

    def get_multiple(self, oids: List[str]) -> Dict[str, Any]:
        """
        Get multiple OIDs in a single request.
        
        Args:
            oids: List of OIDs to query
            
        Returns:
            Dictionary mapping OID to value
        """
        results = {}
        
        try:
            object_types = [ObjectType(ObjectIdentity(oid)) for oid in oids]
            
            iterator = getCmd(
                self._engine,
                self._auth_data,
                self._transport,
                self._context,
                *object_types,
                lookupMib=False
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication:
                self.logger.error(f"SNMP GET error: {errorIndication}")
                return results
            elif errorStatus:
                self.logger.error(f"SNMP GET error: {errorStatus.prettyPrint()}")
                return results
            
            for name, value in varBinds:
                # Filter out SNMP error sentinels — they cannot be converted to
                # numeric types and would cause int() / float() to raise exceptions
                # in vendor parse_device_info() routines.
                v_str = str(value).strip()
                if v_str not in ('noSuchInstance', 'noSuchObject', 'endOfMibView'):
                    results[_oid_to_str(name)] = value
        
        except Exception as e:
            self.logger.error(f"Exception during SNMP GET multiple: {e}")
        
        return results
    
    def test_connection(self) -> bool:
        """
        Test SNMP connectivity.
        
        Returns:
            True if connection successful, False otherwise
        """
        result = self.get("1.3.6.1.2.1.1.1.0")  # sysDescr
        if result:
            self.logger.info(f"SNMP connection test successful")
            return True
        return False

    def get_lldp_neighbors(self) -> Dict[int, Dict[str, str]]:
        """
        Get LLDP neighbor information keyed by local port number.

        Walks LLDP MIB OIDs to discover neighbors on each local port.
        OID structure: 1.0.8802.1.1.2.1.4.1.1.X.timeMark.localPort.remIndex

        All six OID walks are performed independently so that a failure or
        empty result from one (e.g. lldpRemSysName) does not suppress data
        collected by another (e.g. lldpRemPortDesc).  lldpRemSysDesc is used
        as a fallback when lldpRemSysName is absent; lldpRemPortId is used as
        a fallback when lldpRemPortDesc is absent.  The lldpRemManAddrTable is
        also walked to extract the management IPv4 address; when the caller
        (autosync_service) resolves that IP to a known switch name, it can
        fill in system_name even when the remote device does not advertise it
        via lldpRemSysName (observed with some CBS350 ↔ Catalyst 9606 pairs).

        Returns:
            Dict mapping local_port_number ->
                {system_name, port_desc, chassis_id, mgmt_ip}
        """
        def _ensure(d: Dict, key: int) -> None:
            if key not in d:
                d[key] = {'system_name': '', 'port_desc': '', 'chassis_id': '', 'mgmt_ip': ''}

        def _str_val(value) -> str:
            v = str(value).strip()
            return '' if v in ('', 'noSuchInstance', 'noSuchObject', 'endOfMibView') else v

        neighbors: Dict[int, Dict[str, str]] = {}

        # ── 1. lldpRemSysName (.9) — primary system name ──────────────────────
        for oid_str, value in self.get_bulk('1.0.8802.1.1.2.1.4.1.1.9'):
            parts = oid_str.split('.')
            if len(parts) < 2:
                continue
            try:
                local_port = int(parts[-2])
                _ensure(neighbors, local_port)
                v = _str_val(value)
                if v and not neighbors[local_port]['system_name']:
                    neighbors[local_port]['system_name'] = v
            except (ValueError, IndexError):
                pass

        # ── 2. lldpRemSysDesc (.10) — fallback system description ─────────────
        for oid_str, value in self.get_bulk('1.0.8802.1.1.2.1.4.1.1.10'):
            parts = oid_str.split('.')
            if len(parts) < 2:
                continue
            try:
                local_port = int(parts[-2])
                _ensure(neighbors, local_port)
                v = _str_val(value)
                # Use sys_desc only when sys_name is still empty
                if v and not neighbors[local_port]['system_name']:
                    neighbors[local_port]['system_name'] = v
            except (ValueError, IndexError):
                pass

        # ── 3. lldpRemPortDesc (.8) — remote port description ─────────────────
        for oid_str, value in self.get_bulk('1.0.8802.1.1.2.1.4.1.1.8'):
            parts = oid_str.split('.')
            if len(parts) < 2:
                continue
            try:
                local_port = int(parts[-2])
                _ensure(neighbors, local_port)   # independent — no system_name guard
                v = _str_val(value)
                if v and not neighbors[local_port]['port_desc']:
                    neighbors[local_port]['port_desc'] = v
            except (ValueError, IndexError):
                pass

        # ── 4. lldpRemPortId (.7) — port identifier (fallback for port_desc) ──
        for oid_str, value in self.get_bulk('1.0.8802.1.1.2.1.4.1.1.7'):
            parts = oid_str.split('.')
            if len(parts) < 2:
                continue
            try:
                local_port = int(parts[-2])
                _ensure(neighbors, local_port)
                v = _str_val(value)
                # Use port_id only when port_desc is still empty
                if v and not neighbors[local_port]['port_desc']:
                    neighbors[local_port]['port_desc'] = v
            except (ValueError, IndexError):
                pass

        # ── 5. lldpRemChassisId (.5) — chassis identifier ─────────────────────
        for oid_str, value in self.get_bulk('1.0.8802.1.1.2.1.4.1.1.5'):
            parts = oid_str.split('.')
            if len(parts) < 2:
                continue
            try:
                local_port = int(parts[-2])
                _ensure(neighbors, local_port)   # independent
                v = _str_val(value)
                if v and not neighbors[local_port]['chassis_id']:
                    neighbors[local_port]['chassis_id'] = v
            except (ValueError, IndexError):
                pass

        # ── 6. lldpRemManAddrTable — extract management IPv4 address ──────────
        # OID: 1.0.8802.1.1.2.1.4.2.1.4 (lldpRemManAddrIfId)
        # Index: timeMark.portNum.remIndex.addrSubtype.addr[n]
        # For IPv4 (addrSubtype=1): addr = 4 octets appended to index
        # Full OID example: ...4.2.1.4.0.50.1.1.10.1.2.3
        #                             ^  ^  ^ ^  ^^^^^^^^^
        #                      timeMark  |  | |  IPv4 addr
        #                           portNum  | addrSubtype=1
        #                               remIndex
        # Suffix has 8 components for IPv4; base OID has 11 components → total ≥ 19
        for oid_str, _value in self.get_bulk('1.0.8802.1.1.2.1.4.2.1.4'):
            parts = oid_str.split('.')
            if len(parts) < 19:
                continue
            try:
                # Positions from end: [-8]=timeMark, [-7]=portNum, [-6]=remIndex,
                #                     [-5]=addrSubtype, [-4..−1]=IPv4 octets
                addr_subtype = int(parts[-5])
                if addr_subtype != 1:   # only IPv4
                    continue
                local_port = int(parts[-7])
                ip = (f"{int(parts[-4])}.{int(parts[-3])}"
                      f".{int(parts[-2])}.{int(parts[-1])}")
                _ensure(neighbors, local_port)
                if ip and not neighbors[local_port]['mgmt_ip']:
                    neighbors[local_port]['mgmt_ip'] = ip
            except (ValueError, IndexError):
                pass

        # Drop entries that have no useful data at all
        neighbors = {k: v for k, v in neighbors.items()
                     if v['system_name'] or v['port_desc'] or v['chassis_id'] or v['mgmt_ip']}

        return neighbors