"""
Vendor factory for creating appropriate OID mappers.
"""

from typing import Dict, Type
from .base import VendorOIDMapper
from .cisco_catalyst9600 import CiscoCatalyst9600Mapper
from .cisco_cbs350 import CiscoCBS350Mapper


class VendorFactory:
    """Factory for creating vendor-specific OID mappers."""
    
    _mappers: Dict[str, Type[VendorOIDMapper]] = {
        'cisco_catalyst9600': CiscoCatalyst9600Mapper,
        'cisco_cbs350': CiscoCBS350Mapper,
    }
    
    @classmethod
    def get_mapper(cls, vendor: str, model: str) -> VendorOIDMapper:
        """
        Get appropriate OID mapper for vendor and model.
        
        Args:
            vendor: Vendor name (e.g., "cisco")
            model: Model name (e.g., "catalyst9600", "cbs350")
            
        Returns:
            VendorOIDMapper instance
            
        Raises:
            ValueError: If vendor/model combination not supported
        """
        # Normalize vendor and model names
        vendor_lower = vendor.lower()
        model_lower = model.lower()
        
        # Try exact match
        key = f"{vendor_lower}_{model_lower}"
        if key in cls._mappers:
            return cls._mappers[key]()
        
        # Try partial matches
        for mapper_key, mapper_class in cls._mappers.items():
            if vendor_lower in mapper_key and model_lower in mapper_key:
                return mapper_class()
        
        raise ValueError(f"Unsupported vendor/model: {vendor}/{model}. "
                        f"Supported: {', '.join(cls._mappers.keys())}")
    
    @classmethod
    def register_mapper(cls, key: str, mapper_class: Type[VendorOIDMapper]) -> None:
        """
        Register a new vendor mapper.
        
        Args:
            key: Unique key for the mapper (e.g., "cisco_catalyst9600")
            mapper_class: Mapper class to register
        """
        cls._mappers[key] = mapper_class
    
    @classmethod
    def get_supported_vendors(cls) -> list[str]:
        """
        Get list of supported vendor/model combinations.
        
        Returns:
            List of supported combinations
        """
        return list(cls._mappers.keys())
