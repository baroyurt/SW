#!/usr/bin/env python3
"""
Dependency checker for SNMP Worker.
Checks if all required packages are installed before starting the worker.
"""

import sys
import importlib.util

# Required packages and their import names (if different from package name)
REQUIRED_PACKAGES = {
    'pysnmp-lextudio': 'pysnmp',
    'pyasn1': 'pyasn1',
    'pyasyncore': 'asyncore',
    'pyyaml': 'yaml',
    'mysql-connector-python': 'mysql.connector',
    'pymysql': 'pymysql',
    'sqlalchemy': 'sqlalchemy',
    'pytz': 'pytz',
    'python-dotenv': 'dotenv',
    'colorama': 'colorama',
    'python-json-logger': 'pythonjsonlogger',
    'requests': 'requests',
}

OPTIONAL_PACKAGES = {
    'psycopg2-binary': 'psycopg2',
    'python-telegram-bot': 'telegram',
    'aiosmtplib': 'aiosmtplib',
}


def check_package(package_name, import_name):
    """Check if a package is installed."""
    try:
        spec = importlib.util.find_spec(import_name)
        return spec is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def main():
    """Main function to check all dependencies."""
    print("=" * 60)
    print("  SNMP Worker - Dependency Checker")
    print("=" * 60)
    print()
    
    missing_required = []
    missing_optional = []
    
    # Check required packages
    print("Checking Required Packages:")
    print("-" * 60)
    for package_name, import_name in REQUIRED_PACKAGES.items():
        is_installed = check_package(package_name, import_name)
        status = "✓ OK" if is_installed else "✗ MISSING"
        print(f"  [{status}] {package_name}")
        if not is_installed:
            missing_required.append(package_name)
    print()
    
    # Check optional packages
    print("Checking Optional Packages:")
    print("-" * 60)
    for package_name, import_name in OPTIONAL_PACKAGES.items():
        is_installed = check_package(package_name, import_name)
        status = "✓ OK" if is_installed else "- Not installed"
        print(f"  [{status}] {package_name}")
        if not is_installed:
            missing_optional.append(package_name)
    print()
    
    # Summary
    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    
    if missing_required:
        print()
        print("❌ MISSING REQUIRED PACKAGES:")
        print("-" * 60)
        for package in missing_required:
            print(f"  - {package}")
        print()
        print("To install missing packages:")
        print()
        print("  Option 1 (Install all):")
        print("    pip install -r requirements.txt")
        print()
        print("  Option 2 (Install individually):")
        for package in missing_required:
            print(f"    pip install {package}")
        print()
        print("=" * 60)
        return 1
    else:
        print()
        print("✅ All required packages are installed!")
        print()
        if missing_optional:
            print("ℹ️  Optional packages not installed:")
            for package in missing_optional:
                print(f"  - {package}")
            print()
            print("Optional packages provide extra features like:")
            print("  - PostgreSQL database support (psycopg2-binary)")
            print("  - Telegram notifications (python-telegram-bot)")
            print("  - Email notifications (aiosmtplib)")
            print()
        print("✅ Worker can start successfully!")
        print()
        print("=" * 60)
        return 0


if __name__ == "__main__":
    sys.exit(main())
