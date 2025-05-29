#!/usr/bin/env python3
"""
Network Device Model
Defines the NetworkDevice dataclass for representing discovered network devices.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

@dataclass
class NetworkDevice:
    """Represents a discovered network device with its properties"""
    ip: str
    mac: str = ""
    hostname: str = ""
    device_type: str = "Unknown"
    os: str = "Unknown"
    manufacturer: str = ""
    open_ports: Optional[List[int]] = None
    is_router: bool = False

    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
    
    def to_dict(self) -> Dict:
        """Convert device to dictionary for JSON serialization"""
        return asdict(self)
    
    def __str__(self) -> str:
        """String representation of the device"""
        ports = self.open_ports if self.open_ports is not None else []
        ports_str = ','.join(map(str, ports[:5]))
        if len(ports) > 5:
            ports_str += "..."
        
        return (f"Device(IP: {self.ip}, Type: {self.device_type}, "
                f"OS: {self.os}, Hostname: {self.hostname}, "
                f"MAC: {self.mac}, Ports: [{ports_str}])")