#!/usr/bin/env python3
"""
Cisco "show interface status" + gerçek bağlı cihaz MAC'leri — SNMP ile
-----------------------------------------------------------------------
MAC adresleri FDB tablosundan (dot1dTpFdb + dot1qTpFdb) çekilir.
CBS350 gibi switchlerde her VLAN için ayrı SNMP context (@vlanXX) denenir.

Çıktı örneği:
  Port       Name                 Status        Vlan    MAC
  Gi0/0      Workstation-1        connected     10      aa:bb:cc:dd:ee:01
  Gi0/1      Workstation-2        connected     10      aa:bb:cc:dd:ee:02
  Gi0/2      Nokia-VSR trunk      connected     trunk   aa:bb:cc:dd:ee:03
                                                        aa:bb:cc:dd:ee:04
  Gi0/3                           notconnect    1       -

Kullanım:
    python3 sh_int_status_snmp.py [IP] [PORT_SAYISI]
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

# Q-BRIDGE / VLAN
OID_PVID      = "1.3.6.1.2.1.17.7.1.4.5.1.1"
OID_UNTAGGED  = "1.3.6.1.2.1.17.7.1.4.2.1.5"
OID_EGRESS    = "1.3.6.1.2.1.17.7.1.4.2.1.4"

# FDB (MAC address table)
# Yöntem A — dot1d (klasik bridge, VLAN context'e duyarlı)
OID_FDB_PORT   = "1.3.6.1.2.1.17.4.3.1.2"   # dot1dTpFdbPort   MAC→bridge_port
OID_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"   # dot1dTpFdbStatus 3=learned,5=static
OID_BP_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"   # dot1dBasePortIfIndex bridge_port→ifIndex

# Yöntem B — dot1q (VLAN-aware, OID suffix = vlan.mac6byte)
OID_Q_FDB_PORT   = "1.3.6.1.2.1.17.7.1.2.2.1.2"
OID_Q_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"

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
def _auth():
    return UsmUserData(
        V3_USER,
        authKey=V3_AUTH_KEY,
        privKey=V3_PRIV_KEY,
        authProtocol=usmHMACSHAAuthProtocol,
        privProtocol=usmAesCfb128Protocol,
    )

def _ctx(context_name: str = ""):
    return ContextData(contextName=context_name)

def snmp_get(oid: str, context: str = "") -> Optional[Any]:
    try:
        errInd, errStat, _, varBinds = next(
            getCmd(_engine(), _auth(), _transport(), _ctx(context),
                   ObjectType(ObjectIdentity(oid)), lookupMib=False)
        )
        if errInd or errStat:
            return None
        for _, val in varBinds:
            return val
    except Exception:
        return None

def snmp_walk(oid: str, context: str = ""):
    """GETBULK önce, başarısız olursa GETNEXT."""
    results = []
    try:
        for errInd, errStat, _, varBinds in bulkCmd(
            _engine(), _auth(), _transport(), _ctx(context),
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
            for errInd, errStat, _, varBinds in nextCmd(
                _engine(), _auth(), _transport(), _ctx(context),
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

def walk_to_dict(oid: str, context: str = "") -> dict:
    result = {}
    for full_oid, val in snmp_walk(oid, context):
        try:
            result[int(full_oid.split('.')[-1])] = val
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
        clean = pp.replace('0x','').replace(':','').replace(' ','')
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

# ─── INTERFACE ADI ────────────────────────────────────────────────────────────

def shorten_ifname(name: str) -> str:
    for long, short in [("TenGigabitEthernet","Te"),("GigabitEthernet","Gi"),
                        ("FastEthernet","Fa"),("Ethernet","Et")]:
        if name.lower().startswith(long.lower()):
            return short + name[len(long):]
    return name

# ─── VLAN BELİRLEME ──────────────────────────────────────────────────────────

def determine_vlan(port_idx, untagged_map, egress_map, pvid_map, num_ports):
    untagged_vlans, tagged_vlans = set(), set()
    for vlan_id, mask_val in untagged_map.items():
        if port_idx in bitmap_to_ports(mask_val, num_ports):
            untagged_vlans.add(vlan_id)
    for vlan_id, mask_val in egress_map.items():
        if port_idx in bitmap_to_ports(mask_val, num_ports) and vlan_id not in untagged_vlans:
            tagged_vlans.add(vlan_id)

    real_untagged = untagged_vlans - {1}
    real_tagged   = tagged_vlans   - {1}

    if real_tagged:
        return "trunk"
    if real_untagged:
        return str(sorted(real_untagged)[0])
    if 1 in untagged_vlans:
        return "1"
    pvid = pvid_map.get(port_idx)
    return str(pvid) if pvid else "1"

# ─── STATUS ───────────────────────────────────────────────────────────────────

def determine_status(admin_st, oper_st):
    if admin_st == 2:      return "disabled"
    if oper_st == 1:       return "connected"
    if oper_st in (2, 7):  return "notconnect"
    if oper_st == 3:       return "testing"
    return "notconnect"

# ─── MAC TOPLAMA ──────────────────────────────────────────────────────────────

def oid_last_mac(parts: list) -> Optional[str]:
    """OID'nin son 6 elemanını MAC'e çevirir."""
    try:
        return ':'.join(f'{int(b):02x}' for b in parts[-6:])
    except Exception:
        return None

def collect_bp_to_ifindex(context: str = "") -> dict:
    """dot1dBasePortIfIndex → {bridge_port: ifIndex}"""
    result = {}
    for full_oid, val in snmp_walk(OID_BP_IFINDEX, context):
        try:
            bp  = int(full_oid.split('.')[-1])
            ifi = int_val(val)
            if ifi:
                result[bp] = ifi
        except Exception:
            pass
    return result

def collect_dot1d_fdb(context: str = "") -> dict:
    """
    dot1dTpFdb → {bridge_port: {mac, ...}}
    OID suffix = 6 MAC byte (decimal)
    """
    # Status filtresi
    ok_macs = set()
    for full_oid, val in snmp_walk(OID_FDB_STATUS, context):
        try:
            mac = oid_last_mac(full_oid.split('.'))
            if mac and int_val(val) in (3, 5):
                ok_macs.add(mac)
        except Exception:
            pass

    result = {}
    for full_oid, val in snmp_walk(OID_FDB_PORT, context):
        try:
            mac = oid_last_mac(full_oid.split('.'))
            bp  = int_val(val)
            if mac and bp and bp > 0 and (not ok_macs or mac in ok_macs):
                result.setdefault(bp, set()).add(mac)
        except Exception:
            pass
    return result

def collect_dot1q_fdb(context: str = "") -> dict:
    """
    dot1qTpFdb → {bridge_port: {mac, ...}}
    OID suffix = vlan_id + 6 MAC byte
    """
    ok_macs = set()
    for full_oid, val in snmp_walk(OID_Q_FDB_STATUS, context):
        try:
            mac = oid_last_mac(full_oid.split('.'))
            if mac and int_val(val) in (3, 5):
                ok_macs.add(mac)
        except Exception:
            pass

    result = {}
    for full_oid, val in snmp_walk(OID_Q_FDB_PORT, context):
        try:
            mac = oid_last_mac(full_oid.split('.'))
            bp  = int_val(val)
            if mac and bp and bp > 0 and (not ok_macs or mac in ok_macs):
                result.setdefault(bp, set()).add(mac)
        except Exception:
            pass
    return result

def merge_bp_macs(bp_macs: dict, bp_to_if: dict, target: dict):
    """bridge_port → MAC tablosunu ifIndex bazlı hedefe ekler."""
    for bp, macs in bp_macs.items():
        ifi = bp_to_if.get(bp)
        if ifi:
            target.setdefault(ifi, set()).update(macs)

def collect_all_macs(active_vlans: list) -> dict:
    """
    Tüm FDB yöntemlerini deneyerek {ifIndex: [mac, ...]} döndürür.

    Adımlar:
      1. Default context — dot1d + dot1q
      2. Yeterli MAC gelmezse her VLAN için context='vlanXX' dene
         (CBS350 / Catalyst tarzı per-VLAN FDB)
    """
    # Bridge port → ifIndex eşlemesi (genellikle context bağımsız)
    bp_to_if = collect_bp_to_ifindex()
    if not bp_to_if and active_vlans:
        # Bazı switchlerde context gerekebilir
        bp_to_if = collect_bp_to_ifindex(f"vlan{active_vlans[0]}")

    ifindex_macs: dict = {}

    # ── 1. Default context ──────────────────────────────────────────────────
    print("  [4a] dot1d FDB (default context)...", end="", flush=True)
    merge_bp_macs(collect_dot1d_fdb(), bp_to_if, ifindex_macs)
    c1 = sum(len(v) for v in ifindex_macs.values())
    print(f" {c1} MAC")

    print("  [4b] dot1q FDB (default context)...", end="", flush=True)
    merge_bp_macs(collect_dot1q_fdb(), bp_to_if, ifindex_macs)
    c2 = sum(len(v) for v in ifindex_macs.values())
    print(f" {c2} MAC")

    # ── 2. Per-VLAN context ─────────────────────────────────────────────────
    # Eğer default context yeterli MAC getirdiyse bu adım atlanır
    if c2 < 1 and active_vlans:
        print(f"  [4c] Per-VLAN context ({len(active_vlans)} VLAN deneniyor)...")
        for vlan in active_vlans:
            ctx    = f"vlan{vlan}"
            before = sum(len(v) for v in ifindex_macs.values())
            merge_bp_macs(collect_dot1d_fdb(ctx), bp_to_if, ifindex_macs)
            merge_bp_macs(collect_dot1q_fdb(ctx), bp_to_if, ifindex_macs)
            after  = sum(len(v) for v in ifindex_macs.values())
            if after > before:
                print(f"       {ctx}: +{after - before} yeni MAC")
    elif active_vlans:
        # Bazı MACleri kaçırmış olabiliriz, sessizce de dene
        for vlan in active_vlans:
            ctx = f"vlan{vlan}"
            merge_bp_macs(collect_dot1d_fdb(ctx), bp_to_if, ifindex_macs)
            merge_bp_macs(collect_dot1q_fdb(ctx), bp_to_if, ifindex_macs)

    total = sum(len(v) for v in ifindex_macs.values())
    print(f"  Toplam FDB MAC: {total}")
    return {k: sorted(v) for k, v in ifindex_macs.items()}

# ─── ANA PROGRAM ──────────────────────────────────────────────────────────────

def main():
    # Bağlantı testi
    sys_descr = snmp_get("1.3.6.1.2.1.1.1.0")
    if sys_descr is None:
        print("[HATA] Switch'e ulaşılamıyor!")
        print("       IP / SNMPv3 kimlik bilgisi / ağ erişimini kontrol edin.")
        sys.exit(1)
    print(f"Switch : {str_val(sys_descr)[:80]}")
    print(f"IP     : {SWITCH_IP}   Ports: {NUM_PORTS}\n")

    print("SNMP verisi toplanıyor...")

    print("  [1] ifDescr / ifAlias / ifOperStatus / ifAdminStatus...", end="", flush=True)
    ifdescr_map      = walk_to_dict(OID_IF_DESCR)
    ifalias_map      = walk_to_dict(OID_IF_ALIAS)
    oper_status_map  = walk_to_dict(OID_IF_OPER_STATUS)
    admin_status_map = walk_to_dict(OID_IF_ADMIN_STATUS)
    print(" ✓")

    print("  [2] VLAN Untagged/Egress mask...", end="", flush=True)
    untagged_raw, egress_raw = {}, {}
    for full_oid, val in snmp_walk(OID_UNTAGGED):
        try:
            untagged_raw[int(full_oid.split('.')[-1])] = val
        except Exception:
            pass
    for full_oid, val in snmp_walk(OID_EGRESS):
        try:
            egress_raw[int(full_oid.split('.')[-1])] = val
        except Exception:
            pass
    print(f" ✓  ({len(untagged_raw)} VLAN)")

    print("  [3] PVID...", end="", flush=True)
    pvid_map = walk_to_dict(OID_PVID)
    print(f" ✓  ({len(pvid_map)} port)")

    active_vlans = sorted(v for v in (set(untagged_raw) | set(egress_raw)) if v > 0)

    # [4] MAC — tüm yöntemleri dene
    ifindex_to_macs = collect_all_macs(active_vlans)

    # Fiziksel port listesi
    phys_prefixes = ('gi','ge','fa','te','tengig','gigabit','fast','ethernet')
    port_indices = sorted(
        idx for idx, name in ifdescr_map.items()
        if any(str_val(name).lower().startswith(p) for p in phys_prefixes)
    )
    if not port_indices:
        port_indices = sorted(ifdescr_map.keys())[:NUM_PORTS]

    # ── Tablo ────────────────────────────────────────────────────────────────
    C_PORT, C_NAME, C_STAT, C_VLAN = 10, 20, 13, 7

    print()
    print(f"{'Port':<{C_PORT}} {'Name':<{C_NAME}} {'Status':<{C_STAT}} {'Vlan':<{C_VLAN}} MAC")
    print("-" * 75)

    for idx in port_indices[:NUM_PORTS]:
        raw_name  = str_val(ifdescr_map.get(idx, ""))
        port_name = shorten_ifname(raw_name) if raw_name else f"Port{idx}"
        alias     = str_val(ifalias_map.get(idx, "")).strip()
        oper_st   = int_val(oper_status_map.get(idx))
        admin_st  = int_val(admin_status_map.get(idx))
        status    = determine_status(admin_st, oper_st)
        vlan      = determine_vlan(idx, untagged_raw, egress_raw, pvid_map, NUM_PORTS)

        # Yalnızca FDB'den öğrenilen gerçek cihaz MAC'leri
        macs = ifindex_to_macs.get(idx, ["-"])

        for i, mac in enumerate(macs):
            if i == 0:
                print(f"{port_name:<{C_PORT}} {alias:<{C_NAME}} "
                      f"{status:<{C_STAT}} {vlan:<{C_VLAN}} {mac}")
            else:
                # Ek MAC'ler (trunk / hub / birden fazla cihaz)
                indent = " " * (C_PORT + C_NAME + C_STAT + C_VLAN + 4)
                print(f"{indent}{mac}")

    print()

if __name__ == "__main__":
    main()