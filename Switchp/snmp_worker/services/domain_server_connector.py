"""
Domain Server Connector
Connects to Active Directory, LDAP, DHCP servers to resolve MAC addresses to device info
"""

import logging
import socket
import struct
import subprocess
import re
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
import pymysql

logger = logging.getLogger(__name__)


class DomainServerConnector:
    """
    Connects to domain infrastructure to resolve MAC addresses
    Supports: Active Directory (LDAP), DHCP, DNS, NetBIOS
    """
    
    def __init__(self, config: dict = None):
        """
        Initialize domain connector
        
        Args:
            config: Configuration dict with domain server settings
        """
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        self.ldap_host = self.config.get('ldap_host', '')
        self.ldap_port = self.config.get('ldap_port', 389)
        self.ldap_user = self.config.get('ldap_user', '')
        self.ldap_password = self.config.get('ldap_password', '')
        self.ldap_base_dn = self.config.get('ldap_base_dn', '')
        self.dhcp_host = self.config.get('dhcp_host', '')
        self.use_dns = self.config.get('use_dns', True)
        self.use_netbios = self.config.get('use_netbios', True)
        self.cache_duration = self.config.get('cache_duration_days', 30)
        
        # Database config
        self.db_config = self.config.get('database', {})
        
        # Cache
        self._cache = {}
        
        logger.info(f"Domain Server Connector initialized (enabled={self.enabled})")
    
    def lookup_mac(self, mac_address: str) -> Optional[Dict]:
        """
        Lookup MAC address from all available sources
        
        Priority:
        1. Domain cache (30 days)
        2. Active Directory LDAP
        3. DHCP server
        4. DNS/NetBIOS
        5. Database registry (Excel uploads)
        
        Args:
            mac_address: MAC address in format XX:XX:XX:XX:XX:XX
            
        Returns:
            Dict with device info or None
            {
                'mac_address': '00:1A:2B:3C:4D:5E',
                'ip_address': '192.168.1.100',
                'device_name': 'PC-ACCOUNTING-01',
                'user_name': 'john.doe',
                'source': 'domain',
                'last_updated': datetime
            }
        """
        if not mac_address:
            return None
        
        # Normalize MAC address
        mac_address = self._normalize_mac(mac_address)
        
        # Check cache first
        if mac_address in self._cache:
            cached = self._cache[mac_address]
            cache_age = datetime.now() - cached.get('cached_at', datetime.min)
            if cache_age < timedelta(days=self.cache_duration):
                logger.debug(f"MAC {mac_address} found in cache")
                return cached
        
        result = None
        
        if self.enabled:
            # Try domain sources
            result = self._lookup_from_ldap(mac_address)
            if not result:
                result = self._lookup_from_dhcp(mac_address)
            if not result and self.use_dns:
                result = self._lookup_from_dns(mac_address)
        
        # Fallback to database registry (Excel uploads)
        if not result:
            result = self._lookup_from_registry(mac_address)
        
        # Cache result
        if result:
            result['cached_at'] = datetime.now()
            self._cache[mac_address] = result
            logger.info(f"MAC {mac_address} resolved: {result.get('device_name')} ({result.get('source')})")
        else:
            logger.debug(f"MAC {mac_address} not found in any source")
        
        return result
    
    def _lookup_from_ldap(self, mac_address: str) -> Optional[Dict]:
        """
        Query Active Directory LDAP for device info
        
        Args:
            mac_address: Normalized MAC address
            
        Returns:
            Device info dict or None
        """
        if not self.ldap_host or not self.ldap_user:
            return None
        
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL, NTLM
            
            server = Server(self.ldap_host, port=self.ldap_port, get_info=ALL)
            
            # Connect with NTLM authentication (Windows domain)
            conn = Connection(
                server,
                user=self.ldap_user,
                password=self.ldap_password,
                authentication=NTLM,
                auto_bind=True
            )
            
            # Search for computer with MAC address
            search_filter = f'(&(objectClass=computer)(networkAddress={mac_address}))'
            if not self.ldap_base_dn:
                # Try to auto-detect base DN from server info
                self.ldap_base_dn = server.info.other.get('defaultNamingContext', [''])[0]
            
            conn.search(
                search_base=self.ldap_base_dn,
                search_filter=search_filter,
                attributes=['cn', 'name', 'dNSHostName', 'description', 'location']
            )
            
            if conn.entries:
                entry = conn.entries[0]
                device_name = str(entry.cn) if hasattr(entry, 'cn') else str(entry.name)
                dns_name = str(entry.dNSHostName) if hasattr(entry, 'dNSHostName') else None
                
                # Try to resolve IP
                ip_address = None
                if dns_name:
                    try:
                        ip_address = socket.gethostbyname(dns_name)
                    except (socket.gaierror, socket.herror):
                        pass
                
                conn.unbind()
                
                return {
                    'mac_address': mac_address,
                    'ip_address': ip_address,
                    'device_name': device_name,
                    'user_name': None,
                    'source': 'domain',
                    'last_updated': datetime.now()
                }
            
            conn.unbind()
            
        except ImportError:
            logger.warning("ldap3 module not installed. Install with: pip install ldap3")
        except Exception as e:
            logger.error(f"LDAP query error for {mac_address}: {e}")
        
        return None
    
    def _lookup_from_dhcp(self, mac_address: str) -> Optional[Dict]:
        """
        Query DHCP server for lease information
        
        Args:
            mac_address: Normalized MAC address
            
        Returns:
            Device info dict or None
        """
        if not self.dhcp_host:
            return None
        
        try:
            # Try Windows DHCP server query
            if self.dhcp_host:
                result = self._query_windows_dhcp(mac_address)
                if result:
                    return result
            
            # Could add support for ISC DHCP, etc.
            
        except Exception as e:
            logger.error(f"DHCP query error for {mac_address}: {e}")
        
        return None
    
    def _query_windows_dhcp(self, mac_address: str) -> Optional[Dict]:
        """
        Query Windows DHCP server using netsh or PowerShell
        
        Args:
            mac_address: Normalized MAC address
            
        Returns:
            Device info dict or None
        """
        try:
            # Validate DHCP host to prevent command injection
            if not re.match(r'^[a-zA-Z0-9\.\-]+$', self.dhcp_host):
                logger.warning(f"Invalid DHCP host format: {self.dhcp_host}")
                return None
            
            # Try netsh command
            cmd = [
                'netsh', 'dhcp', 'server', self.dhcp_host,
                'scope', 'show', 'clients'
            ]
            
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=5)
            output = output.decode('utf-8', errors='ignore')
            
            # Parse output to find MAC address
            # Format varies, basic parsing:
            for line in output.split('\n'):
                if mac_address.replace(':', '-').lower() in line.lower():
                    # Try to extract IP and hostname
                    parts = line.split()
                    if len(parts) >= 2:
                        ip_address = parts[0]
                        device_name = parts[-1] if len(parts) > 2 else None
                        
                        return {
                            'mac_address': mac_address,
                            'ip_address': ip_address,
                            'device_name': device_name,
                            'user_name': None,
                            'source': 'dhcp',
                            'last_updated': datetime.now()
                        }
        
        except subprocess.TimeoutExpired:
            logger.warning(f"DHCP query timeout for {mac_address}")
        except subprocess.CalledProcessError as e:
            logger.debug(f"DHCP query failed: {e}")
        except OSError as e:
            logger.error(f"DHCP query OS error: {e}")
        
        return None
    
    def _lookup_from_dns(self, mac_address: str) -> Optional[Dict]:
        """
        Try to resolve via DNS/NetBIOS if we have an IP
        
        Args:
            mac_address: Normalized MAC address
            
        Returns:
            Device info dict or None
        """
        # This requires knowing IP first from another source
        # Kept as placeholder for future enhancement
        return None
    
    def _lookup_from_registry(self, mac_address: str) -> Optional[Dict]:
        """
        Lookup from database registry (Excel uploads, manual entries)
        
        Args:
            mac_address: Normalized MAC address
            
        Returns:
            Device info dict or None
        """
        try:
            conn = pymysql.connect(
                host=self.db_config.get('host', 'localhost'),
                user=self.db_config.get('user', 'root'),
                password=self.db_config.get('password', ''),
                database=self.db_config.get('database', 'switchdb'),
                charset='utf8mb4'
            )
            
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            cursor.execute("""
                SELECT 
                    mac_address, ip_address, device_name, user_name,
                    location, department, source, updated_at
                FROM mac_device_registry
                WHERE mac_address = %s
            """, (mac_address,))
            
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if row:
                return {
                    'mac_address': row['mac_address'],
                    'ip_address': row['ip_address'],
                    'device_name': row['device_name'],
                    'user_name': row['user_name'],
                    'location': row.get('location'),
                    'department': row.get('department'),
                    'source': row.get('source', 'registry'),
                    'last_updated': row['updated_at']
                }
        
        except Exception as e:
            logger.error(f"Registry lookup error for {mac_address}: {e}")
        
        return None
    
    def bulk_lookup(self, mac_addresses: list) -> Dict[str, Dict]:
        """
        Lookup multiple MAC addresses efficiently
        
        Args:
            mac_addresses: List of MAC addresses
            
        Returns:
            Dict mapping MAC to device info
        """
        results = {}
        for mac in mac_addresses:
            result = self.lookup_mac(mac)
            if result:
                results[mac] = result
        
        return results
    
    def update_port_descriptions(self, device_id: int, port_macs: Dict[int, list]):
        """
        Update port descriptions with device names from MAC lookups
        
        Args:
            device_id: SNMP device ID
            port_macs: Dict mapping port_number to list of MAC addresses
        """
        try:
            conn = pymysql.connect(
                host=self.db_config.get('host', 'localhost'),
                user=self.db_config.get('user', 'root'),
                password=self.db_config.get('password', ''),
                database=self.db_config.get('database', 'switchdb'),
                charset='utf8mb4'
            )
            
            cursor = conn.cursor()
            
            for port_num, mac_list in port_macs.items():
                if not mac_list:
                    continue
                
                # Lookup each MAC
                device_names = []
                for mac in mac_list:
                    info = self.lookup_mac(mac)
                    if info and info.get('device_name'):
                        device_names.append(info['device_name'])
                
                if device_names:
                    # Update port description
                    description = ', '.join(device_names[:3])  # Max 3 devices
                    if len(device_names) > 3:
                        description += f' (+{len(device_names)-3} more)'
                    
                    cursor.execute("""
                        UPDATE port_status_data
                        SET description = %s
                        WHERE device_id = %s AND port_number = %s
                    """, (description, device_id, port_num))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Updated port descriptions for device {device_id}")
        
        except Exception as e:
            logger.error(f"Error updating port descriptions: {e}")
    
    @staticmethod
    def _normalize_mac(mac_address: str) -> str:
        """
        Normalize MAC address to XX:XX:XX:XX:XX:XX format
        
        Args:
            mac_address: MAC in any format
            
        Returns:
            Normalized MAC address
        """
        # Remove all non-hex characters
        mac = re.sub(r'[^0-9A-Fa-f]', '', mac_address)
        
        # Insert colons every 2 characters
        if len(mac) == 12:
            return ':'.join(mac[i:i+2] for i in range(0, 12, 2)).upper()
        
        return mac_address  # Return as-is if can't normalize
