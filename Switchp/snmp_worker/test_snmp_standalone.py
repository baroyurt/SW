#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP Worker - Standalone Test Script
Bu script veritabanı olmadan SNMP test yapmak için kullanılır.
"""

import sys
import logging
from datetime import datetime

# Check Python version
if sys.version_info < (3, 7):
    print("\nHATA: Python 3.7 veya üzeri gereklidir!")
    print(f"Mevcut Python versiyonu: {sys.version}")
    sys.exit(1)

# Try to import required packages
try:
    # Explicit imports for pysnmp-lextudio 5.x compatibility
    # The wildcard import doesn't work properly in newer versions
    from pysnmp.hlapi import (
        UsmUserData, usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
        SnmpEngine, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd, bulkCmd
    )
    import yaml
except ImportError as e:
    print("\nHATA: Gerekli Python paketleri eksik!")
    print("Çözüm: pip install -r requirements.txt")
    print(f"\nEksik paket: {e}")
    sys.exit(1)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('snmp_test')


class SNMPTester:
    """Standalone SNMP test class."""
    
    def __init__(self, host: str, username: str = 'snmpuser', 
                 auth_password: str = 'AuthPass123', 
                 priv_password: str = 'PrivPass123'):
        """Initialize SNMP tester."""
        self.host = host
        self.username = username
        self.auth_password = auth_password
        self.priv_password = priv_password
        
    def test_connection(self):
        """Test SNMP connection to device."""
        logger.info(f"Testing SNMP connection to {self.host}...")
        
        try:
            # Setup SNMPv3 authentication
            auth_data = UsmUserData(
                self.username,
                self.auth_password,
                self.priv_password,
                authProtocol=usmHMACSHAAuthProtocol,
                privProtocol=usmAesCfb128Protocol
            )
            
            # Try to get system description
            iterator = getCmd(
                SnmpEngine(),
                auth_data,
                UdpTransportTarget((self.host, 161), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication:
                logger.error(f"SNMP Hatası: {errorIndication}")
                return False
            elif errorStatus:
                logger.error(f"SNMP Hatası: {errorStatus.prettyPrint()}")
                return False
            else:
                for varBind in varBinds:
                    logger.info(f"Bağlantı BAŞARILI!")
                    logger.info(f"Cihaz: {varBind[1]}")
                    return True
                    
        except Exception as e:
            logger.error(f"SNMP test hatası: {e}")
            return False
            
        return False
    
    def get_port_info(self, port_count: int = 28):
        """Get port information."""
        logger.info(f"Port bilgileri alınıyor (1-{port_count})...")
        
        ports = []
        
        try:
            auth_data = UsmUserData(
                self.username,
                self.auth_password,
                self.priv_password,
                authProtocol=usmHMACSHAAuthProtocol,
                privProtocol=usmAesCfb128Protocol
            )
            
            for i in range(1, port_count + 1):
                # Get port operational status
                iterator = getCmd(
                    SnmpEngine(),
                    auth_data,
                    UdpTransportTarget((self.host, 161), timeout=2, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8.' + str(i)))  # ifOperStatus
                )
                
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                
                if errorIndication:
                    logger.warning(f"Port {i}: SNMP hatası - {errorIndication}")
                    continue
                elif errorStatus:
                    logger.warning(f"Port {i}: Durum okunamadı")
                    continue
                    
                for varBind in varBinds:
                    status = int(varBind[1])
                    status_text = "UP" if status == 1 else "DOWN"
                    port_type = "PoE" if i <= 24 else "SFP"
                    
                    port_info = {
                        'port': i,
                        'type': port_type,
                        'status': status_text,
                        'status_code': status
                    }
                    ports.append(port_info)
                    logger.info(f"  Port GE{i} ({port_type}): {status_text}")
                    
        except Exception as e:
            logger.error(f"Port bilgisi alma hatası: {e}")
            
        return ports


def main():
    """Main entry point."""
    print("\n" + "="*60)
    print("SNMP Worker - Standalone Test")
    print("="*60)
    print()
    
    # Test configuration
    # NOTE: Update these values to match your environment
    # For production use, consider reading from environment variables:
    #   host = os.getenv('SNMP_HOST', '172.18.1.214')
    #   username = os.getenv('SNMP_USERNAME', 'snmpuser')
    #   auth_password = os.getenv('SNMP_AUTH_PASSWORD', 'AuthPass123')
    #   priv_password = os.getenv('SNMP_PRIV_PASSWORD', 'PrivPass123')
    test_config = {
        'host': '172.18.1.214',  # Replace with your switch IP
        'username': 'snmpuser',
        'auth_password': 'AuthPass123',  # Replace with your auth password
        'priv_password': 'PrivPass123'   # Replace with your priv password
    }
    
    print(f"Test Cihazı: {test_config['host']}")
    print(f"SNMP Kullanıcı: {test_config['username']}")
    print()
    
    # Create tester
    tester = SNMPTester(**test_config)
    
    # Test connection
    print("1. Bağlantı testi yapılıyor...")
    if not tester.test_connection():
        print("\nHATA: SNMP bağlantısı başarısız!")
        print("\nOlası nedenler:")
        print("  1. Cihaz erişilebilir değil (network bağlantısı)")
        print("  2. SNMP şifreleri yanlış")
        print("  3. SNMP servisi çalışmıyor")
        print("  4. Firewall/güvenlik duvarı engel olabilir")
        print()
        sys.exit(1)
    
    print()
    print("2. Port bilgileri alınıyor...")
    ports = tester.get_port_info(28)
    
    # Statistics
    active_ports = [p for p in ports if p['status'] == 'UP']
    print()
    print("="*60)
    print("SONUÇ:")
    print(f"  Toplam Port: {len(ports)}")
    print(f"  Aktif Port: {len(active_ports)}")
    print(f"  Pasif Port: {len(ports) - len(active_ports)}")
    print("="*60)
    print()
    print("Test BAŞARILI!")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest kullanıcı tarafından durduruldu (Ctrl+C)")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nKRİTİK HATA: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
