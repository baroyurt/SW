#!/usr/bin/env python3
"""
CBS350 VLAN OID Test v2
------------------------
Yöntem 5 (Egress Mask) + Yöntem 6 (Untagged Mask) kombinasyonu.
Access / Trunk port ayrımı yapar, gereksiz tekrar SNMP walk yok.

Kullanım:
    python3 vlan_oid_test.py [IP] [PORT_SAYISI]

Varsayılan:
    IP          = 172.18.1.214
    PORT_SAYISI = 28
"""

import sys
import binascii
import traceback
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

# ─── SNMP IMPORT ────────────────────────────────────────────────────────────
try:
    from pysnmp.hlapi import (
        SnmpEngine, UdpTransportTarget, ContextData,
        UsmUserData,
        ObjectType, ObjectIdentity,
        getCmd, nextCmd, bulkCmd,
        usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
    )
    SNMP_OK = True
except ImportError as e:
    print(f"[HATA] pysnmp import edilemedi: {e}")
    print("       pip install pysnmp-lextudio")
    sys.exit(1)

# ─── SNMP HELPERS ────────────────────────────────────────────────────────────

def _engine():
    return SnmpEngine()

def _transport():
    return UdpTransportTarget((SWITCH_IP, SNMP_PORT), timeout=TIMEOUT, retries=RETRIES)

def _ctx():
    return ContextData()

def _auth():
    return UsmUserData(
        V3_USER,
        authKey=V3_AUTH_KEY,
        privKey=V3_PRIV_KEY,
        authProtocol=usmHMACSHAAuthProtocol,
        privProtocol=usmAesCfb128Protocol,
    )

def snmp_get(oid: str) -> Optional[Any]:
    """Tek OID GET."""
    try:
        errInd, errStat, _, varBinds = next(
            getCmd(_engine(), _auth(), _transport(), _ctx(),
                   ObjectType(ObjectIdentity(oid)),
                   lookupMib=False)
        )
        if errInd or errStat:
            return None
        for name, val in varBinds:
            return val
    except Exception:
        return None

def snmp_walk_bulk(oid: str, max_rep: int = 50):
    """GETBULK walk."""
    results = []
    try:
        for (errInd, errStat, _, varBinds) in bulkCmd(
            _engine(), _auth(), _transport(), _ctx(),
            0, max_rep,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
            lookupMib=False
        ):
            if errInd or errStat:
                break
            for name, val in varBinds:
                results.append((str(name), val))
    except Exception:
        pass
    return results

def snmp_walk_next(oid: str):
    """GETNEXT walk (fallback)."""
    results = []
    try:
        for (errInd, errStat, _, varBinds) in nextCmd(
            _engine(), _auth(), _transport(), _ctx(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
            lookupMib=False
        ):
            if errInd or errStat:
                break
            for name, val in varBinds:
                results.append((str(name), val))
    except Exception:
        pass
    return results

def snmp_walk(oid: str):
    """Önce GETBULK, başarısız olursa GETNEXT dener."""
    rows = snmp_walk_bulk(oid)
    if not rows:
        rows = snmp_walk_next(oid)
    return rows

# ─── BİTMAP YARDIMCILARI ─────────────────────────────────────────────────────

def octetstring_to_bytes(val) -> Optional[bytes]:
    """pysnmp OctetString → bytes."""
    if isinstance(val, bytes):
        return val
    # asOctets — en güvenilir yol
    try:
        return val.asOctets()
    except Exception:
        pass
    # prettyPrint → hex parse
    try:
        pp = val.prettyPrint()
        clean = pp.replace('0x', '').replace(':', '').replace(' ', '')
        if all(c in '0123456789abcdefABCDEF' for c in clean) and len(clean) % 2 == 0:
            return binascii.unhexlify(clean)
    except Exception:
        pass
    # asNumbers
    try:
        return bytes(val.asNumbers())
    except Exception:
        pass
    # bytearray cast
    try:
        return bytes(bytearray(val))
    except Exception:
        pass
    return None

def bitmap_to_ports(mask_val, num_ports: int = None) -> list:
    """Egress/Untagged bitmap → port listesi."""
    if num_ports is None:
        num_ports = NUM_PORTS
    raw = octetstring_to_bytes(mask_val)
    if not raw:
        return []
    ports = []
    for i in range(1, num_ports + 1):
        byte_pos = (i - 1) // 8
        bit_pos  = 7 - ((i - 1) % 8)
        if byte_pos < len(raw) and (raw[byte_pos] >> bit_pos) & 1:
            ports.append(i)
    return ports

# ─── VERİ TOPLAMA ─────────────────────────────────────────────────────────────

def collect_untagged_mask():
    """dot1q.VlanStaticUntaggedPorts → {vlan_id: [port, ...]}"""
    result = {}
    rows = snmp_walk("1.3.6.1.2.1.17.7.1.4.2.1.5")
    for oid, val in rows:
        try:
            vlan_id = int(oid.split('.')[-1])
            ports   = bitmap_to_ports(val)
            result[vlan_id] = ports
        except Exception:
            pass
    return result

def collect_egress_mask():
    """dot1q.VlanStaticEgressPorts → {vlan_id: [port, ...]}"""
    result = {}
    rows = snmp_walk("1.3.6.1.2.1.17.7.1.4.2.1.4")
    for oid, val in rows:
        try:
            vlan_id = int(oid.split('.')[-1])
            ports   = bitmap_to_ports(val)
            result[vlan_id] = ports
        except Exception:
            pass
    return result

def collect_pvid():
    """dot1q.PortVlanId / PVID → {port_idx: vlan_id}"""
    result = {}
    rows = snmp_walk("1.3.6.1.2.1.17.7.1.4.5.1.1")
    for oid, val in rows:
        try:
            idx  = int(oid.split('.')[-1])
            vlan = int(val)
            result[idx] = vlan
        except Exception:
            pass
    return result

def collect_ifdescr():
    """ifDescr → {ifIndex: "GigabitEthernet1", ...}"""
    result = {}
    rows = snmp_walk("1.3.6.1.2.1.2.2.1.2")
    for oid, val in rows:
        try:
            idx = int(oid.split('.')[-1])
            result[idx] = str(val)
        except Exception:
            pass
    return result

# ─── ÇÖZÜMLEME ────────────────────────────────────────────────────────────────

def build_port_vlan_map(untagged_map, egress_map, pvid_map):
    """Untagged + Egress + PVID → port bazında VLAN bilgisi."""
    port_untagged = {}
    for vlan_id, ports in untagged_map.items():
        for p in ports:
            port_untagged.setdefault(p, []).append(vlan_id)

    port_tagged = {}
    for vlan_id, ports in egress_map.items():
        untagged_ports = set(untagged_map.get(vlan_id, []))
        for p in ports:
            if p not in untagged_ports:
                port_tagged.setdefault(p, []).append(vlan_id)

    result = {}
    for port in range(1, NUM_PORTS + 1):
        untagged_vlans = sorted(port_untagged.get(port, []))
        tagged_vlans   = sorted(port_tagged.get(port, []))
        pvid           = pvid_map.get(port)

        untagged_real  = [v for v in untagged_vlans if v != 1]
        tagged_real    = [v for v in tagged_vlans   if v != 1]

        if tagged_real and untagged_real:
            mode   = "trunk"
            access = untagged_real[0]
            trunks = tagged_real
        elif tagged_real:
            mode   = "trunk"
            access = pvid if pvid and pvid != 1 else 1
            trunks = tagged_real
        elif untagged_real:
            mode   = "access"
            access = untagged_real[0]
            trunks = []
        elif untagged_vlans == [1] or (pvid == 1):
            mode   = "access"
            access = 1
            trunks = []
        else:
            mode   = "unknown"
            access = pvid
            trunks = []

        result[port] = {
            "mode":         mode,
            "access_vlan":  access,
            "trunk_vlans":  trunks,
            "pvid":         pvid,
        }
    return result

# ─── YAZDIRMA ─────────────────────────────────────────────────────────────────

def section(title):
    print(f"\n{'='*65}")
    print(f"  {title}")
    print('='*65)

def print_vlan_table(port_map, ifdescr_map):
    section("PORT VLAN TABLOSU")
    hdr = f"  {'PORT':<6} {'IF_ADI':<22} {'MOD':<8} {'ACCESS_VLAN':>11} {'PVID':>6}  TRUNK_VLAN_LİSTESİ"
    print(hdr)
    print("  " + "-"*80)
    for port in range(1, NUM_PORTS + 1):
        info     = port_map[port]
        if_name  = ifdescr_map.get(port, f"GE{port}")
        short_if = if_name[-22:] if len(if_name) > 22 else if_name
        mode     = info["mode"]
        access   = str(info["access_vlan"]) if info["access_vlan"] is not None else "-"
        pvid_str = str(info["pvid"])        if info["pvid"]        is not None else "-"
        trunks   = ", ".join(str(v) for v in info["trunk_vlans"]) if info["trunk_vlans"] else "-"
        print(f"  GE{port:<4} {short_if:<22} {mode:<8} {access:>11} {pvid_str:>6}  {trunks}")

def print_vlan_members(untagged_map, egress_map):
    section("VLAN ÜYELİK TABLOSU")
    all_vlans = sorted(set(untagged_map) | set(egress_map))
    for vlan_id in all_vlans:
        untagged = sorted(untagged_map.get(vlan_id, []))
        egress   = sorted(egress_map.get(vlan_id, []))
        tagged   = sorted(set(egress) - set(untagged))
        if not egress:
            continue
        print(f"\n  VLAN {vlan_id}:")
        print(f"    Untagged (access) : {untagged if untagged else '-'}")
        print(f"    Tagged   (trunk)  : {tagged   if tagged   else '-'}")
        print(f"    Egress   (tüm)    : {egress}")

def print_summary(port_map):
    section("ÖZET")
    access_ports  = {p: v for p, v in port_map.items() if v["mode"] == "access" and v["access_vlan"] and v["access_vlan"] != 1}
    trunk_ports   = {p: v for p, v in port_map.items() if v["mode"] == "trunk"}
    default_ports = {p: v for p, v in port_map.items() if v["mode"] == "access" and (not v["access_vlan"] or v["access_vlan"] == 1)}
    unknown_ports = {p: v for p, v in port_map.items() if v["mode"] == "unknown"}

    print(f"\n  Access portlar  (non-default VLAN) : {len(access_ports)}")
    print(f"  Trunk portlar                      : {len(trunk_ports)}")
    print(f"  Default VLAN 1 portlar             : {len(default_ports)}")
    print(f"  Bilinemeyen portlar                : {len(unknown_ports)}")

    if trunk_ports:
        print(f"\n  Trunk portlar detayı:")
        for p, v in sorted(trunk_ports.items()):
            print(f"    GE{p}: native={v['access_vlan']}, trunk={v['trunk_vlans']}")

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    print(f"\nCBS350 VLAN Test v2 | {SWITCH_IP} | {NUM_PORTS} port")
    print(f"SNMPv3 → kullanıcı={V3_USER}")

    section("BAĞLANTI TESTİ (sysDescr)")
    sys_descr = snmp_get("1.3.6.1.2.1.1.1.0")
    if sys_descr is None:
        print("[HATA] Switch'e ulaşılamıyor!")
        sys.exit(1)
    pp = sys_descr.prettyPrint() if hasattr(sys_descr, 'prettyPrint') else str(sys_descr)
    print(f"  sysDescr = {pp!r}")

    section("VERİ TOPLANIYOR...")

    print("  [1/4] Untagged mask toplanıyor...")
    untagged_map = collect_untagged_mask()
    print(f"        {'✅' if untagged_map else '❌'} {len(untagged_map)} VLAN girdisi")

    print("  [2/4] Egress mask toplanıyor...")
    egress_map = collect_egress_mask()
    print(f"        {'✅' if egress_map else '❌'} {len(egress_map)} VLAN girdisi")

    print("  [3/4] PVID toplanıyor...")
    pvid_map = collect_pvid()
    print(f"        {'✅' if pvid_map else '⚠️ '} {len(pvid_map)} port girdisi")

    print("  [4/4] ifDescr toplanıyor...")
    ifdescr_map = collect_ifdescr()
    print(f"        {'✅' if ifdescr_map else '⚠️ '} {len(ifdescr_map)} interface girdisi")

    if not untagged_map and not egress_map:
        print("\n[HATA] Ne untagged ne egress mask verisi alınamadı.")
        sys.exit(1)

    port_map = build_port_vlan_map(untagged_map, egress_map, pvid_map)

    print_vlan_members(untagged_map, egress_map)
    print_vlan_table(port_map, ifdescr_map)
    print_summary(port_map)
    print()

if __name__ == "__main__":
    main()
