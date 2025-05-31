#!/usr/bin/env python3
"""
Network Utilities
Helper functions for network operations like ping, hostname resolution, etc.
"""

import subprocess
import socket
import ipaddress
import re
from typing import List, Optional
from scapy.all import srp
from scapy.layers.l2 import ARP, Ether

def get_network_info() -> tuple[str, str]:
    """
    Get network range and router IP
    Returns: (network_range, router_ip)
    """
    try:
        # Get local IP and network info first
        local_ip = None
        
        # Method 1: Try to get local IP by connecting to external host
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
        except:
            pass
        
        # Method 2: Windows ipconfig parsing
        if not local_ip:
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
                if result.stdout:
                    # Look for active adapter with IPv4 address
                    lines = result.stdout.split('\n')
                    current_adapter = ""
                    for i, line in enumerate(lines):
                        if "adapter" in line and ":" in line:
                            current_adapter = line.strip()
                        elif "IPv4 Address" in line and "192.168" in line:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                local_ip = ip_match.group(1)
                                print(f"Found local IP: {local_ip}")
                                break
            except Exception as e:
                print(f"ipconfig parsing failed: {e}")
        
        # Method 3: Get default gateway
        gateway_ip = None
        try:
            # Windows route command
            result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                  capture_output=True, text=True, shell=True)
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if '0.0.0.0' in line and '0.0.0.0' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            potential_gateway = parts[2]
                            if re.match(r'\d+\.\d+\.\d+\.\d+', potential_gateway):
                                gateway_ip = potential_gateway
                                break
        except:
            pass
        
        # Method 4: Parse ipconfig for gateway
        if not gateway_ip:
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
                if result.stdout:
                    gateway_match = re.search(r'Default Gateway.*?(\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if gateway_match:
                        gateway_ip = gateway_match.group(1)
            except:
                pass
        
        # Determine network range from local IP
        if local_ip:
            # Assume /24 subnet
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            network_range = str(network)
            
            # Set router IP - use detected gateway or assume .1
            if gateway_ip:
                router_ip = gateway_ip
            else:
                router_ip = str(network.network_address + 1)
                
            print(f"Network detected: {network_range}")
            print(f"Router IP: {router_ip}")
            return network_range, router_ip
        
        # Ultimate fallback
        print("Could not detect network automatically, using fallback")
        return "192.168.1.0/24", "192.168.1.1"
            
    except Exception as e:
        print(f"Error getting network info: {e}")
        # Default fallback
        return "192.168.1.0/24", "192.168.1.1"

def ping_host(ip: str) -> bool:
    """Ping a host to check if it's alive"""
    try:
        # Windows ping command
        result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                              capture_output=True, text=True, timeout=3)
        return result.returncode == 0
    except:
        return False

def get_hostname(ip: str) -> str:
    """Get hostname for IP address"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def get_mac_address(ip: str) -> str:
    """Attempts to get the MAC address using Scapy, falls back to ARP table lookup."""
    try:
        answered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)[0]
        if answered:
            return answered[0][1].hwsrc
    except Exception as e:
        print(f"Scapy MAC lookup failed for {ip}: {e}")

    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, shell=True)
        for line in result.stdout.split('\n'):
            if ip in line:
                mac_match = re.search(r'([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}', line)
                if mac_match:
                    return mac_match.group(0)
    except Exception as e:
        print(f"ARP table lookup failed for {ip}: {e}")

    return ""

def scan_ports(ip: str, ports: List[int]) -> List[int]:
    """Scan specific ports on a host"""
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def get_mac_vendor(mac: str) -> str:
    """Get manufacturer from MAC address OUI"""
    if not mac or len(mac) < 8:
        return ""
    
    try:
        oui = mac.replace(':', '').replace('-', '').upper()[:6]
        # You could implement a local OUI database lookup here
        # For now, return empty string
        return ""
    except:
        return ""