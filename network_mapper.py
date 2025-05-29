#!/usr/bin/env python3
"""
Network Mapper
Creates visual network maps of discovered devices.
"""

from typing import List
from network_device import NetworkDevice

import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Try importing matplotlib
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not available. Install with: pip install matplotlib")

class NetworkMapper:
    def __init__(self, devices: List[NetworkDevice], network_range: str, router_ip: str):
        self.devices = devices
        self.network_range = network_range
        self.router_ip = router_ip
        
        # Colors for different device types
        self.colors = {
            'Router': '#FF6B6B',
            'Windows PC': '#4ECDC4',
            'Server': '#45B7D1',
            'Linux/Unix': '#96CEB4',
            'iOS Device': '#FFEAA7',
            'Android Device': '#DDA0DD',
            'Printer': '#98D8C8',
            'Camera': '#F7DC6F',
            'Unknown Device': '#BDC3C7'
        }

    def create_network_map(self, save_path: str = "network_map.png"):
        """Create a visual network map"""
        if not MATPLOTLIB_AVAILABLE:
            print("Matplotlib not available. Cannot create network map.")
            return
            
        if not self.devices:
            print("No devices to map!")
            return
        
        # Create figure
        fig, ax = plt.subplots(1, 1, figsize=(14, 10))
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 8)
        ax.axis('off')
        
        # Find router
        router = next((d for d in self.devices if d.is_router), None)
        
        # Position router in center
        if router:
            router_pos = (5, 4)
            self._draw_device(ax, router, router_pos, 
                            self.colors.get(router.device_type, self.colors['Router']), 
                            is_router=True)
        
        # Position other devices in a circle around router
        other_devices = [d for d in self.devices if not d.is_router]
        if other_devices:
            import math
            radius = 2.5
            angle_step = 2 * math.pi / len(other_devices)
            
            for i, device in enumerate(other_devices):
                angle = i * angle_step
                x = 5 + radius * math.cos(angle)
                y = 4 + radius * math.sin(angle)
                
                # Draw connection line to router
                if router:
                    ax.plot([5, x], [4, y], 'k--', alpha=0.3, linewidth=1)
                
                # Draw device
                color = self.colors.get(device.device_type, self.colors['Unknown Device'])
                self._draw_device(ax, device, (x, y), color)
        
        # Add title and legend
        plt.title(f"Network Map - {self.network_range}\n{len(self.devices)} devices found", 
                 fontsize=16, fontweight='bold', pad=20)
        
        # Create legend
        legend_elements = []
        used_types = set(d.device_type for d in self.devices)
        for device_type in used_types:
            color = self.colors.get(device_type, self.colors['Unknown Device'])
            legend_elements.append(patches.Patch(color=color, label=device_type))
        
        ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(0, 1))
        
        # Add network info box
        info_text = f"Network: {self.network_range}\nRouter: {self.router_ip}\nDevices: {len(self.devices)}"
        ax.text(0.02, 0.02, info_text, transform=ax.transAxes, fontsize=10,
               bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgray", alpha=0.8))
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Network map saved as: {save_path}")
        plt.show()

    def _draw_device(self, ax, device, pos, color, is_router=False):
        """Draw a device on the network map"""
        x, y = pos
        
        # Device icon (circle)
        size = 0.4 if is_router else 0.3
        circle = patches.Circle((x, y), size, facecolor=color, edgecolor='black', linewidth=2)
        ax.add_patch(circle)
        
        # Device type icon (text)
        icon = "🌐 " if is_router else "💻 " if "PC" in device.device_type else "📱 " if "Device" in device.device_type else "🖥️ "
        ax.text(x, y, icon, ha='center', va='center', fontsize=20)
        
        # Labels
        # IP address
        ax.text(x, y-0.6, device.ip, ha='center', va='center', fontsize=8, fontweight='bold')
        
        # Device type
        ax.text(x, y-0.8, device.device_type, ha='center', va='center', fontsize=7)
        
        # Hostname (if available)
        if device.hostname:
            hostname = device.hostname[:15] + "..." if len(device.hostname) > 15 else device.hostname
            ax.text(x, y-1.0, hostname, ha='center', va='center', fontsize=6, style='italic')