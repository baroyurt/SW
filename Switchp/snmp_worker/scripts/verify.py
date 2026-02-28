#!/usr/bin/env python3
"""
Simple verification script for SNMP Worker.
Tests basic configuration loading and module imports.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    """Test that all modules can be imported."""
    print("Testing module imports...")
    
    try:
        from snmp_worker.config.config_loader import Config
        print("✓ Config loader imported")
        
        from snmp_worker.core.snmp_client import SNMPClient
        print("✓ SNMP client imported")
        
        from snmp_worker.core.database_manager import DatabaseManager
        print("✓ Database manager imported")
        
        from snmp_worker.core.alarm_manager import AlarmManager
        print("✓ Alarm manager imported")
        
        from snmp_worker.core.polling_engine import PollingEngine
        print("✓ Polling engine imported")
        
        from snmp_worker.vendors.factory import VendorFactory
        print("✓ Vendor factory imported")
        
        from snmp_worker.services.telegram_service import TelegramNotificationService
        print("✓ Telegram service imported")
        
        from snmp_worker.services.email_service import EmailNotificationService
        print("✓ Email service imported")
        
        from snmp_worker.models.database import Base, SNMPDevice
        print("✓ Database models imported")
        
        from snmp_worker.utils.logger import setup_logging
        print("✓ Logger utilities imported")
        
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False


def test_vendor_factory():
    """Test vendor factory."""
    print("\nTesting vendor factory...")
    
    try:
        from snmp_worker.vendors.factory import VendorFactory
        
        supported = VendorFactory.get_supported_vendors()
        print(f"✓ Supported vendors: {', '.join(supported)}")
        
        # Test getting a mapper
        mapper = VendorFactory.get_mapper("cisco", "catalyst9600")
        print(f"✓ Created mapper for Cisco Catalyst 9600")
        
        mapper = VendorFactory.get_mapper("cisco", "cbs350")
        print(f"✓ Created mapper for Cisco CBS350")
        
        return True
    except Exception as e:
        print(f"✗ Vendor factory error: {e}")
        return False


def test_config_loading():
    """Test configuration loading."""
    print("\nTesting configuration loading...")
    
    try:
        from snmp_worker.config.config_loader import Config
        
        # Try loading example config
        config = Config("snmp_worker/config/config.example.yml")
        print(f"✓ Configuration loaded")
        print(f"  - Database: {config.database.name}")
        print(f"  - Poll interval: {config.polling.interval}s")
        print(f"  - Devices configured: {len(config.devices)}")
        print(f"  - Telegram enabled: {config.telegram.enabled}")
        print(f"  - Email enabled: {config.email.enabled}")
        
        return True
    except Exception as e:
        print(f"✗ Configuration error: {e}")
        return False


def test_database_models():
    """Test database models."""
    print("\nTesting database models...")
    
    try:
        from snmp_worker.models.database import (
            SNMPDevice, DevicePollingData, PortStatusData,
            Alarm, AlarmHistory, DeviceStatus, PortStatus
        )
        
        # Test creating model instances
        device = SNMPDevice(
            name="Test Device",
            ip_address="192.168.1.1",
            vendor="cisco",
            model="catalyst9600"
        )
        print(f"✓ Created SNMPDevice model: {device}")
        
        return True
    except Exception as e:
        print(f"✗ Database model error: {e}")
        return False


def test_snmp_client():
    """Test SNMP client creation."""
    print("\nTesting SNMP client...")
    
    try:
        from snmp_worker.core.snmp_client import SNMPClient
        
        # Test v2c client
        client = SNMPClient(
            host="192.168.1.1",
            version="2c",
            community="public"
        )
        print(f"✓ Created SNMP v2c client")
        
        # Test v3 client
        client = SNMPClient(
            host="192.168.1.1",
            version="3",
            username="user",
            auth_protocol="SHA",
            auth_password="authpass",
            priv_protocol="AES",
            priv_password="privpass"
        )
        print(f"✓ Created SNMP v3 client")
        
        return True
    except Exception as e:
        print(f"✗ SNMP client error: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("SNMP Worker Verification Script")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("Module Imports", test_imports()))
    results.append(("Vendor Factory", test_vendor_factory()))
    results.append(("Configuration", test_config_loading()))
    results.append(("Database Models", test_database_models()))
    results.append(("SNMP Client", test_snmp_client()))
    
    # Print summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("-" * 60)
    print(f"Passed: {passed}/{total}")
    print("=" * 60)
    
    if passed == total:
        print("\n✓ All tests passed! System is ready.")
        return 0
    else:
        print("\n✗ Some tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
