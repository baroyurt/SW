#!/usr/bin/env python3
"""
Cisco Catalyst 9200 "show interface status" + MAC adresleri — SNMP ile
-----------------------------------------------------------------------
Sadece fiziksel portları gösterir (Gi1/0/x, Gi1/1/x vb.)

Kullanım:
    python3 c9200_int_status.py [IP] [PORT_SAYISI]
"""

import sys
import binascii
from typing import Any, Optional, Dict, Set, List

# ─── AYARLAR ────────────────────────────────────────────────────────────────
SWITCH_IP   = sys.argv[1] if len(sys.argv) > 1 else "172.18.1.226"
SNMP_PORT   = 161
NUM_PORTS   = int(sys.argv[2]) if len(sys.argv) > 2 else 54
TIMEOUT     = 5
RETRIES     = 2

V3_USER     = "snmpuser"
V3_AUTH_KEY = "AuthPass123"
V3_PRIV_KEY = "PrivPass123"

# ─── OID TANIMLAR ───────────────────────────────────────────────────────────
# Temel interface bilgileri
OID_IF_DESCR        = "1.3.6.1.2.1.2.2.1.2"      # ifDescr
OID_IF_ALIAS        = "1.3.6.1.2.1.31.1.1.1.18"  # ifAlias
OID_IF_OPER_STATUS  = "1.3.6.1.2.1.2.2.1.8"      # ifOperStatus
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"      # ifAdminStatus
OID_IF_NAME         = "1.3.6.1.2.1.31.1.1.1.1"   # ifName
OID_IF_TYPE         = "1.3.6.1.2.1.2.2.1.3"      # ifType

# VLAN bilgileri
OID_VLAN_PORT_PVID  = "1.3.6.1.2.1.17.7.1.4.5.1.1"    # dot1qPvid

# CISCO VLAN OID'leri
OID_CISCO_VLAN_PORT = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"  # vmVlan

# MAC tablosu OID'leri
OID_FDB_PORT         = "1.3.6.1.2.1.17.4.3.1.2"        # dot1dTpFdbPort
OID_BRIDGE_PORT_IF   = "1.3.6.1.2.1.17.1.4.1.2"        # dot1dBasePortIfIndex
OID_DOT1Q_FDB_PORT   = "1.3.6.1.2.1.17.7.1.2.2.1.2"    # dot1qTpFdbPort
OID_CISCO_MAC_PORT   = "1.3.6.1.4.1.9.9.215.1.1.8.1.4" # cMacPort

# ─── SNMP IMPORT ────────────────────────────────────────────────────────────
try:
    from pysnmp.hlapi import (
        SnmpEngine, UdpTransportTarget, ContextData,
        UsmUserData,
        ObjectType, ObjectIdentity,
        getCmd, nextCmd,
        usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
    )
except ImportError as e:
    print(f"[HATA] pysnmp import edilemedi: {e}")
    print("       pip install pysnmp-lextudio")
    sys.exit(1)

# ─── SNMP HELPERS ────────────────────────────────────────────────────────────

class SNMPSession:
    """SNMP oturumu"""
    
    def __init__(self, ip: str, port: int = 161):
        self.ip = ip
        self.port = port
        self.engine = SnmpEngine()
        self.auth = UsmUserData(
            V3_USER,
            authKey=V3_AUTH_KEY,
            privKey=V3_PRIV_KEY,
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        )
        self.transport = UdpTransportTarget((ip, port), timeout=TIMEOUT, retries=RETRIES)
    
    def _ctx(self, context: str = ""):
        return ContextData(contextName=context)
    
    def get(self, oid: str) -> Optional[Any]:
        """SNMP GET"""
        try:
            errInd, errStat, _, varBinds = next(
                getCmd(self.engine, self.auth, self.transport, self._ctx(""),
                       ObjectType(ObjectIdentity(oid)))
            )
            if errInd or errStat:
                return None
            for _, val in varBinds:
                return val
        except Exception:
            return None
    
    def walk(self, oid: str) -> List[tuple]:
        """SNMP WALK"""
        results = []
        try:
            for errInd, errStat, _, varBinds in nextCmd(
                self.engine, self.auth, self.transport, self._ctx(""),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if errInd or errStat:
                    break
                for name, val in varBinds:
                    results.append((str(name), val))
        except Exception:
            pass
        return results

# ─── YARDIMCI FONKSİYONLAR ──────────────────────────────────────────────────

def val_to_str(val) -> str:
    """SNMP değerini string'e çevir"""
    if val is None:
        return ""
    try:
        return str(val)
    except Exception:
        return ""

def val_to_int(val) -> Optional[int]:
    """SNMP değerini integer'a çevir"""
    try:
        return int(val)
    except Exception:
        return None

def oid_to_mac(oid: str) -> Optional[str]:
    """OID'nin sonundaki MAC adresini çıkar"""
    try:
        parts = oid.split('.')
        # Son 6 rakam MAC adresi
        if len(parts) >= 6:
            mac_parts = parts[-6:]
            # Sadece rakam olanları al
            mac_bytes = []
            for x in mac_parts:
                if x.isdigit():
                    mac_bytes.append(int(x))
            if len(mac_bytes) == 6:
                return ':'.join(f'{b:02x}' for b in mac_bytes)
    except Exception:
        pass
    return None

def is_physical_port(ifname: str, iftype: Optional[int] = None) -> bool:
    """Portun fiziksel olup olmadığını kontrol et"""
    if ifname.lower().startswith('gi'):
        return True
    if ifname.lower().startswith('gigabitethernet'):
        return True
    if ifname.lower().startswith('fastethernet'):
        return True
    if ifname.lower().startswith('tengigabitethernet'):
        return True
    if ifname.lower().startswith('twentyfivegige'):
        return True
    # ifType kontrolü (6 = ethernetCsmacd)
    if iftype == 6:
        return True
    return False

def shorten_ifname(name: str) -> str:
    """Interface adını kısalt"""
    replacements = [
        ("GigabitEthernet", "Gi"),
        ("FastEthernet", "Fa"),
        ("TenGigabitEthernet", "Te"),
        ("TwentyFiveGigE", "Twe"),
        ("Ethernet", "Eth"),
    ]
    result = name
    for long, short in replacements:
        if result.startswith(long):
            result = short + result[len(long):]
            break
    return result

# ─── INTERFACE BİLGİLERİ TOPLAMA ────────────────────────────────────────────

def collect_interface_info(session: SNMPSession) -> dict:
    """Sadece fiziksel interface bilgilerini topla"""
    print("  [1] Fiziksel port bilgileri toplanıyor...")
    
    # Tüm interfaceleri topla
    all_ifnames = {}
    all_iftypes = {}
    all_alias = {}
    all_oper = {}
    all_admin = {}
    
    # ifName
    for oid, val in session.walk(OID_IF_NAME):
        try:
            idx = int(oid.split('.')[-1])
            all_ifnames[idx] = val_to_str(val)
        except Exception:
            pass
    
    # ifType
    for oid, val in session.walk(OID_IF_TYPE):
        try:
            idx = int(oid.split('.')[-1])
            all_iftypes[idx] = val_to_int(val)
        except Exception:
            pass
    
    # ifAlias
    for oid, val in session.walk(OID_IF_ALIAS):
        try:
            idx = int(oid.split('.')[-1])
            all_alias[idx] = val_to_str(val)
        except Exception:
            pass
    
    # operStatus
    for oid, val in session.walk(OID_IF_OPER_STATUS):
        try:
            idx = int(oid.split('.')[-1])
            all_oper[idx] = val_to_int(val)
        except Exception:
            pass
    
    # adminStatus
    for oid, val in session.walk(OID_IF_ADMIN_STATUS):
        try:
            idx = int(oid.split('.')[-1])
            all_admin[idx] = val_to_int(val)
        except Exception:
            pass
    
    # Sadece fiziksel portları filtrele
    phys_indices = []
    phys_info = {
        'names': {},
        'alias': {},
        'oper': {},
        'admin': {}
    }
    
    for idx in sorted(all_ifnames.keys()):
        ifname = all_ifnames.get(idx, "")
        iftype = all_iftypes.get(idx)
        
        if is_physical_port(ifname, iftype):
            phys_indices.append(idx)
            phys_info['names'][idx] = ifname
            if idx in all_alias:
                phys_info['alias'][idx] = all_alias[idx]
            if idx in all_oper:
                phys_info['oper'][idx] = all_oper[idx]
            if idx in all_admin:
                phys_info['admin'][idx] = all_admin[idx]
    
    print(f"     ✓ Toplam {len(all_ifnames)} interface, {len(phys_indices)} fiziksel port")
    
    return {
        'names': phys_info['names'],
        'alias': phys_info['alias'],
        'oper': phys_info['oper'],
        'admin': phys_info['admin'],
        'phys_indices': phys_indices[:NUM_PORTS]
    }

# ─── VLAN BİLGİLERİ TOPLAMA ─────────────────────────────────────────────────

def collect_vlan_info(session: SNMPSession) -> dict:
    """VLAN bilgilerini topla"""
    print("  [2] VLAN bilgileri toplanıyor...")
    
    pvid_map = {}
    for oid, val in session.walk(OID_VLAN_PORT_PVID):
        try:
            idx = int(oid.split('.')[-1])
            pvid_map[idx] = val_to_int(val) or 1
        except Exception:
            pass
    
    cisco_vlan_map = {}
    for oid, val in session.walk(OID_CISCO_VLAN_PORT):
        try:
            idx = int(oid.split('.')[-1])
            cisco_vlan_map[idx] = val_to_int(val) or 1
        except Exception:
            pass
    
    print(f"     ✓ {len(pvid_map)} port PVID bulundu")
    
    return {
        'pvid': pvid_map,
        'cisco_vlan': cisco_vlan_map
    }

# ─── MAC ADRESLERİ TOPLAMA ─────────────────────────────────────────────────

def collect_mac_addresses(session: SNMPSession, phys_indices: List[int]) -> Dict[int, List[str]]:
    """MAC adreslerini topla - sadece fiziksel portlar için"""
    print("  [3] MAC adresleri toplanıyor...")
    
    ifindex_macs: Dict[int, Set[str]] = {}
    
    # Bridge port mapping
    bp_to_if = {}
    for oid, val in session.walk(OID_BRIDGE_PORT_IF):
        try:
            bp = int(oid.split('.')[-1])
            if_idx = val_to_int(val)
            if if_idx and if_idx in phys_indices:  # Sadece fiziksel portlar
                bp_to_if[bp] = if_idx
        except Exception:
            pass
    
    print(f"     Bridge port mapping: {len(bp_to_if)} kayıt")
    
    # dot1dTpFdb'den MAC'leri topla
    fdb_count = 0
    for oid, val in session.walk(OID_FDB_PORT):
        try:
            mac = oid_to_mac(oid)
            bp = val_to_int(val)
            
            if mac and bp and bp in bp_to_if:
                if_idx = bp_to_if[bp]
                if if_idx in phys_indices:
                    if if_idx not in ifindex_macs:
                        ifindex_macs[if_idx] = set()
                    ifindex_macs[if_idx].add(mac)
                    fdb_count += 1
        except Exception:
            pass
    
    print(f"     dot1dTpFdb: {fdb_count} MAC")
    
    # dot1qTpFdbPort'dan MAC'leri topla
    qbridge_count = 0
    for oid, val in session.walk(OID_DOT1Q_FDB_PORT):
        try:
            mac = oid_to_mac(oid)
            if_idx = val_to_int(val)
            
            if mac and if_idx and if_idx in phys_indices:
                if if_idx not in ifindex_macs:
                    ifindex_macs[if_idx] = set()
                ifindex_macs[if_idx].add(mac)
                qbridge_count += 1
        except Exception:
            pass
    
    if qbridge_count > 0:
        print(f"     dot1qTpFdb: +{qbridge_count} MAC")
    
    # CISCO MAC'leri topla
    cisco_count = 0
    for oid, val in session.walk(OID_CISCO_MAC_PORT):
        try:
            mac = oid_to_mac(oid)
            if_idx = val_to_int(val)
            
            if mac and if_idx and if_idx in phys_indices:
                if if_idx not in ifindex_macs:
                    ifindex_macs[if_idx] = set()
                ifindex_macs[if_idx].add(mac)
                cisco_count += 1
        except Exception:
            pass
    
    if cisco_count > 0:
        print(f"     CISCO MAC: +{cisco_count} MAC")
    
    # Sonuçları düzenle
    result = {}
    total_macs = 0
    
    for idx in sorted(phys_indices):
        if idx in ifindex_macs and ifindex_macs[idx]:
            macs = sorted(ifindex_macs[idx])[:5]  # En fazla 5 MAC göster
            result[idx] = macs
            total_macs += len(macs)
    
    if total_macs == 0:
        print("\n     ! UYARI: Hiç MAC adresi bulunamadı")
        print("       Sebepler:")
        print("       - Portlarda trafik yok (MAC tablosu boş)")
        print("       - SNMP yetkileri yetersiz")
        print("       - Farklı SNMP context gerekebilir\n")
    
    return result

# ─── PORT DURUMU ve VLAN BELİRLEME ──────────────────────────────────────────

def determine_status(admin: Optional[int], oper: Optional[int]) -> str:
    """Port durumunu belirle"""
    if admin == 2:
        return "disabled"
    if oper == 1:
        return "connected"
    return "notconnect"

def determine_vlan(port_idx: int, vlan_info: dict) -> str:
    """Port'un VLAN'ını belirle"""
    pvid = vlan_info['pvid'].get(port_idx)
    if pvid:
        return str(pvid)
    
    cisco_vlan = vlan_info['cisco_vlan'].get(port_idx)
    if cisco_vlan:
        return str(cisco_vlan)
    
    return "1"

# ─── ANA PROGRAM ────────────────────────────────────────────────────────────

def main():
    # SNMP oturumu oluştur
    session = SNMPSession(SWITCH_IP, SNMP_PORT)
    
    # Bağlantı testi
    sys_descr = session.get("1.3.6.1.2.1.1.1.0")
    if sys_descr is None:
        print("[HATA] Switch'e ulaşılamıyor!")
        print(f"       IP: {SWITCH_IP}")
        print("       SNMPv3 bilgilerini kontrol edin.")
        sys.exit(1)
    
    print(f"\n{'='*60}")
    print(f"Cisco Catalyst 9200 Interface Status")
    print(f"{'='*60}")
    print(f"Switch : {val_to_str(sys_descr)[:80]}")
    print(f"IP     : {SWITCH_IP}")
    print(f"{'='*60}\n")
    
    print("SNMP verisi toplanıyor...\n")
    
    # Interface bilgileri (sadece fiziksel portlar)
    if_info = collect_interface_info(session)
    
    if not if_info['phys_indices']:
        print("[HATA] Hiç fiziksel port bulunamadı!")
        sys.exit(1)
    
    # VLAN bilgileri
    vlan_info = collect_vlan_info(session)
    
    # MAC adresleri
    mac_map = collect_mac_addresses(session, if_info['phys_indices'])
    
    # Tablo çıktısı
    print("\n" + "="*85)
    
    # Başlıklar
    C_PORT = 12
    C_NAME = 30
    C_STAT = 12
    C_VLAN = 8
    
    print(f"{'Port':<{C_PORT}} {'Name':<{C_NAME}} {'Status':<{C_STAT}} {'Vlan':<{C_VLAN}} MAC Address(es)")
    print("-" * 85)
    
    # Her port için çıktı
    macsiz_sayac = 0
    
    for idx in if_info['phys_indices']:
        # Port adı
        port_name = if_info['names'].get(idx, f"Port{idx}")
        port_name = shorten_ifname(port_name)
        
        # Açıklama
        alias = if_info['alias'].get(idx, "").strip()
        
        # Durum
        status = determine_status(
            if_info['admin'].get(idx),
            if_info['oper'].get(idx)
        )
        
        # VLAN
        vlan = determine_vlan(idx, vlan_info)
        
        # MAC'ler
        macs = mac_map.get(idx, ["-"])
        if macs == ["-"]:
            macsiz_sayac += 1
        
        for i, mac in enumerate(macs):
            if i == 0:
                print(f"{port_name:<{C_PORT}} {alias:<{C_NAME}} "
                      f"{status:<{C_STAT}} {vlan:<{C_VLAN}} {mac}")
            else:
                indent = " " * (C_PORT + C_NAME + C_STAT + C_VLAN + 4)
                print(f"{indent}{mac}")
    
    # Özet
    print("-" * 85)
    connected = sum(1 for idx in if_info['phys_indices'] 
                   if if_info['oper'].get(idx) == 1)
    disabled = sum(1 for idx in if_info['phys_indices'] 
                  if if_info['admin'].get(idx) == 2)
    
    print(f"Özet: {len(if_info['phys_indices'])} port gösteriliyor")
    print(f"      {connected} connected, {disabled} disabled")
    print(f"      {macsiz_sayac} portta MAC yok")
    
    if macsiz_sayac == len(if_info['phys_indices']):
        print("\nNOT: Hiç MAC adresi bulunamadı. Olası sebepler:")
        print("     - Switch'te MAC tablosu boş (trafik yok)")
        print("     - SNMP community'si MAC tablosunu okuma yetkisine sahip değil")
        print("     - Farklı bir SNMP versiyonu gerekebilir")
    
    print()

if __name__ == "__main__":
    main()