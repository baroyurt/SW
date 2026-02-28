#!/usr/bin/env python3
"""
Cisco "show interface status" benzeri çıktı — SNMP ile
-------------------------------------------------------
Çıktı örneği:
  Port     Name                Status       Vlan
  Gi0/0    Workstation-1       connected    10
  Gi0/1    Workstation-2       connected    10
  Gi0/2    Nokia-VSR trunk     connected    trunk
  Gi0/3                        notconnect   1

Kullanım:
    python3 sh_int_status_snmp.py [IP] [PORT_SAYISI]

Varsayılan:
    IP          = 172.18.1.214
    PORT_SAYISI = 28
"""

import sys
import binascii
from typing import Any, Optional

# ─── AYARLAR ────────────────────────────────────────────────────────────────
SWITCH_IP   = sys.argv[1] if len(sys.argv) > 1 else "172.18.1.214"
SNMP_PORT   = 161
NUM_PORTS   = int(sys.argv[2]) if len(sys.argv) > 2 else 28
TIMEOUT     = 3
RETRIES     = 1

V3_USER     = "snmpuser"
V3_AUTH_KEY = "AuthPass123"
V3_PRIV_KEY = "PrivPass123"

# ─── OID TANIMLAR ───────────────────────────────────────────────────────────
OID_IF_DESCR        = "1.3.6.1.2.1.2.2.1.2"
OID_IF_ALIAS        = "1.3.6.1.2.1.31.1.1.1.18"
OID_IF_OPER_STATUS  = "1.3.6.1.2.1.2.2.1.8"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_PVID            = "1.3.6.1.2.1.17.7.1.4.5.1.1"
OID_UNTAGGED        = "1.3.6.1.2.1.17.7.1.4.2.1.5"
OID_EGRESS          = "1.3.6.1.2.1.17.7.1.4.2.1.4"

# ─── SNMP IMPORT ────────────────────────────────────────────────────────────
try:
    from pysnmp.hlapi import (
        SnmpEngine, UdpTransportTarget, ContextData,
        UsmUserData,
        ObjectType, ObjectIdentity,
        getCmd, nextCmd, bulkCmd,
        usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
    )
except ImportError as e:
    print(f"[HATA] pysnmp import edilemedi: {e}")
    print("       pip install pysnmp-lextudio")
    sys.exit(1)

# ─── SNMP HELPERS ────────────────────────────────────────────────────────────

def _engine():    return SnmpEngine()
def _transport(): return UdpTransportTarget((SWITCH_IP, SNMP_PORT), timeout=TIMEOUT, retries=RETRIES)
def _ctx():       return ContextData()
def _auth():
    return UsmUserData(
        V3_USER,
        authKey=V3_AUTH_KEY,
        privKey=V3_PRIV_KEY,
        authProtocol=usmHMACSHAAuthProtocol,
        privProtocol=usmAesCfb128Protocol,
    )

def snmp_get(oid: str) -> Optional[Any]:
    try:
        errInd, errStat, _, varBinds = next(
            getCmd(_engine(), _auth(), _transport(), _ctx(),
                   ObjectType(ObjectIdentity(oid)), lookupMib=False)
        )
        if errInd or errStat:
            return None
        for _, val in varBinds:
            return val
    except Exception:
        return None

def snmp_walk(oid: str):
    """GETBULK, başarısız olursa GETNEXT."""
    results = []
    try:
        for (errInd, errStat, _, varBinds) in bulkCmd(
            _engine(), _auth(), _transport(), _ctx(),
            0, 50,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False, lookupMib=False
        ):
            if errInd or errStat:
                break
            for name, val in varBinds:
                results.append((str(name), val))
    except Exception:
        pass

    if not results:
        try:
            for (errInd, errStat, _, varBinds) in nextCmd(
                _engine(), _auth(), _transport(), _ctx(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False, lookupMib=False
            ):
                if errInd or errStat:
                    break
                for name, val in varBinds:
                    results.append((str(name), val))
        except Exception:
            pass
    return results

def walk_to_dict(oid: str) -> dict:
    result = {}
    for full_oid, val in snmp_walk(oid):
        try:
            idx = int(full_oid.split('.')[-1])
            result[idx] = val
        except Exception:
            pass
    return result

def str_val(val) -> str:
    if val is None:
        return ""
    try:
        return val.prettyPrint()
    except Exception:
        return str(val)

def int_val(val) -> Optional[int]:
    try:
        return int(val)
    except Exception:
        return None

# ─── BİTMAP ──────────────────────────────────────────────────────────────────

def octetstring_to_bytes(val) -> Optional[bytes]:
    if isinstance(val, bytes):
        return val
    try:
        return val.asOctets()
    except Exception:
        pass
    try:
        pp = val.prettyPrint()
        clean = pp.replace('0x', '').replace(':', '').replace(' ', '')
        if all(c in '0123456789abcdefABCDEF' for c in clean) and len(clean) % 2 == 0:
            return binascii.unhexlify(clean)
    except Exception:
        pass
    try:
        return bytes(val.asNumbers())
    except Exception:
        pass
    return None

def bitmap_to_ports(mask_val, num_ports: int) -> set:
    raw = octetstring_to_bytes(mask_val)
    if not raw:
        return set()
    ports = set()
    for i in range(1, num_ports + 1):
        byte_pos = (i - 1) // 8
        bit_pos  = 7 - ((i - 1) % 8)
        if byte_pos < len(raw) and (raw[byte_pos] >> bit_pos) & 1:
            ports.add(i)
    return ports

# ─── INTERFACE ADI KISALTMA ───────────────────────────────────────────────────

def shorten_ifname(name: str) -> str:
    abbrevs = [
        ("TenGigabitEthernet", "Te"),
        ("GigabitEthernet",    "Gi"),
        ("FastEthernet",       "Fa"),
        ("Ethernet",           "Et"),
    ]
    for long, short in abbrevs:
        if name.lower().startswith(long.lower()):
            return short + name[len(long):]
    return name

# ─── VLAN BELİRLEME ───────────────────────────────────────────────────────────

def determine_vlan(port_idx: int, untagged_map: dict, egress_map: dict, pvid_map: dict, num_ports: int) -> str:
    untagged_vlans = set()
    for vlan_id, mask_val in untagged_map.items():
        ports = bitmap_to_ports(mask_val, num_ports)
        if port_idx in ports:
            untagged_vlans.add(vlan_id)

    tagged_vlans = set()
    for vlan_id, mask_val in egress_map.items():
        ports = bitmap_to_ports(mask_val, num_ports)
        if port_idx in ports and vlan_id not in untagged_vlans:
            tagged_vlans.add(vlan_id)

    real_untagged = untagged_vlans - {1}
    real_tagged   = tagged_vlans   - {1}

    if real_tagged:
        return "trunk"
    elif real_untagged:
        return str(sorted(real_untagged)[0])
    elif 1 in untagged_vlans:
        return "1"
    else:
        pvid = pvid_map.get(port_idx)
        if pvid:
            return str(pvid)
        return "1"

# ─── STATUS ÇÖZÜMLE ───────────────────────────────────────────────────────────

def determine_status(admin_status: Optional[int], oper_status: Optional[int]) -> str:
    if admin_status == 2:
        return "disabled"
    if oper_status == 1:
        return "connected"
    if oper_status in (2, 7):
        return "notconnect"
    if oper_status == 3:
        return "testing"
    return "notconnect"

# ─── ANA PROGRAM ──────────────────────────────────────────────────────────────

def main():
    sys_descr = snmp_get("1.3.6.1.2.1.1.1.0")
    if sys_descr is None:
        print("[HATA] Switch'e ulaşılamıyor!")
        sys.exit(1)
    print(f"Switch : {str_val(sys_descr)[:80]}")
    print(f"IP     : {SWITCH_IP}   Ports: {NUM_PORTS}")
    print()

    print("SNMP verisi toplanıyor...", end="", flush=True)

    ifdescr_map      = walk_to_dict(OID_IF_DESCR)
    ifalias_map      = walk_to_dict(OID_IF_ALIAS)
    oper_status_map  = walk_to_dict(OID_IF_OPER_STATUS)
    admin_status_map = walk_to_dict(OID_IF_ADMIN_STATUS)

    untagged_raw = {}
    for full_oid, val in snmp_walk(OID_UNTAGGED):
        try:
            vlan_id = int(full_oid.split('.')[-1])
            untagged_raw[vlan_id] = val
        except Exception:
            pass

    egress_raw = {}
    for full_oid, val in snmp_walk(OID_EGRESS):
        try:
            vlan_id = int(full_oid.split('.')[-1])
            egress_raw[vlan_id] = val
        except Exception:
            pass

    pvid_map = walk_to_dict(OID_PVID)

    print(" tamam.\n")

    phys_prefixes = ('gi', 'ge', 'fa', 'te', 'tengig', 'gigabit', 'fast', 'ethernet')
    port_indices = sorted(
        idx for idx, name in ifdescr_map.items()
        if any(str_val(name).lower().startswith(p) for p in phys_prefixes)
    )

    if not port_indices:
        port_indices = sorted(ifdescr_map.keys())[:NUM_PORTS]

    print(f"{'Port':<10} {'Name':<20} {'Status':<13} {'Vlan'}")
    print("-" * 55)

    for idx in port_indices[:NUM_PORTS]:
        raw_name  = str_val(ifdescr_map.get(idx, ""))
        port_name = shorten_ifname(raw_name) if raw_name else f"Port{idx}"
        alias     = str_val(ifalias_map.get(idx, "")).strip()
        oper_st   = int_val(oper_status_map.get(idx))
        admin_st  = int_val(admin_status_map.get(idx))
        status    = determine_status(admin_st, oper_st)
        vlan      = determine_vlan(idx, untagged_raw, egress_raw, pvid_map, NUM_PORTS)

        print(f"{port_name:<10} {alias:<20} {status:<13} {vlan}")

    print()

if __name__ == "__main__":
    main()
