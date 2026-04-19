"""
Cisco Catalyst C9300L OID mapper.

Dedicated mapper for Cisco Catalyst 9300L series (e.g., C9300L-48P-4X).
Inherits all logic from CiscoC9200Mapper but overrides MAC collection to
scan only the site-allowed data VLANs via per-VLAN SNMPv3 contexts.

Only VLANs in ALLOWED_VLANS = {30, 40, 50, 70, 130, 140, 150, 254, 1500}
are ever queried.  This mirrors the proven behavior of the standalone
C9300L.py diagnostic script which uses the same whitelist.  VLAN 70 is
always included regardless of what dot1qPvid or vmVlan discovery returns,
because on IOS-XE access ports typically report PVID=0 and vmVlan may not
reflect every active VLAN.
"""

import logging
from typing import Dict, List, Any, Optional

from .cisco_c9200 import CiscoC9200Mapper

_log = logging.getLogger(__name__)


class CiscoC9300Mapper(CiscoC9200Mapper):
    """OID mapper for Cisco Catalyst C9300L switches.

    MAC collection is restricted to ALLOWED_VLANS = {30, 40, 50, 70, 130, 140, 150, 254, 1500}.
    This whitelist approach guarantees that VLAN 70 (and other data VLANs) are
    always scanned even when dot1qPvid returns 0 / 1 for all access ports
    (common on C9300L IOS-XE) and vmVlan discovery misses VLANs with no
    currently-assigned ports.
    """

    DEFAULT_PORTS = 52  # C9300L-48P-4X: 48 GE + 4 x10G

    # Whitelist of data VLANs to scan — identical to C9300L.py ALLOWED_VLANS.
    # Includes WiFi-adjacent VLANs (30 GUEST, 40 VIP) so physical devices on
    # those VLANs (when VLAN 70 / AP is absent) are also captured.
    # Also includes 150 (JACKPOT) and 1500 (DRGT) for multi-MAC Hub detection.
    ALLOWED_VLANS: frozenset = frozenset({30, 40, 50, 70, 130, 140, 150, 254, 1500})

    def __init__(self):
        super().__init__()
        self.model_name = 'c9300l'

    def collect_mac_with_vlan_contexts(
        self,
        snmp_client: Any,
        active_vlans: Optional[List[int]] = None,
    ) -> Dict[int, List[str]]:
        """Collect MACs using per-VLAN SNMPv3 contexts for ALLOWED_VLANS only.

        On C9300L IOS-XE, dot1qPvid typically returns 0 or 1 for all access
        ports so discovery-based VLAN lists miss data VLANs like 70.  Rather
        than relying on discovery, we always scan exactly ALLOWED_VLANS
        {30, 40, 50, 70, 130, 140, 150, 254, 1500}.

        Args:
            snmp_client: SNMPClient instance.
            active_vlans: Ignored — ALLOWED_VLANS whitelist is used instead.

        Returns:
            Dict mapping sequential port_number → list of MAC strings.
        """
        data_vlans = sorted(self.ALLOWED_VLANS)
        _log.info('C9300: scanning %d allowed VLAN(s): %s', len(data_vlans), data_vlans)
        return super().collect_mac_with_vlan_contexts(snmp_client, data_vlans)
