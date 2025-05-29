# Network Scanner & Mapper

A comprehensive Python tool to scan your local network, identify devices, and create visual network maps.

## Features

- **Network Discovery**: Automatically detects your network range and router
- **Device Identification**: Identifies device types (Windows PC, mobile devices, servers, etc.)
- **OS Detection**: Attempts to identify operating systems based on network characteristics
- **Port Scanning**: Scans common ports to identify services
- **Visual Mapping**: Creates visual network topology maps
- **Multiple Scan Methods**: Supports both basic ping scanning and advanced nmap scanning
- **Export Results**: Save scan results to JSON files

## Installation

1. **Clone or download the files** to a directory on your computer:
   ```
   network_scanner/
   ├── main.py
   ├── network_scanner.py
   ├── network_device.py
   ├── network_utils.py
   ├── device_identifier.py
   ├── network_mapper.py
   ├── requirements.txt
   └── README.md
   ```

2. **Install Python dependencies** (optional but recommended):
   ```bash
   pip install -r requirements.txt
   ```

   **Note**: The scanner will work with just Python's standard library, but installing the optional packages enables additional features:
   - `python-nmap`: Advanced scanning capabilities
   - `scapy`: Enhanced network packet analysis
   - `matplotlib`: Visual network maps
   - `networkx`: Network topology analysis

## Usage

### Basic Usage

Run the main script:
```bash
python main.py
```

### What It Does

1. **Auto-detects your network** (e.g., 192.168.1.0/24)
2. **Scans for live devices** using ping or nmap
3. **Identifies device types** based on:
   - Open ports
   - Hostnames
   - Network behavior
4. **Creates a visual map** (if matplotlib is installed)
5. **Exports results** to JSON

### Sample Output

```
Network detected: 192.168.1.0/24
Router IP: 192.168.1.1
Scanning network: 192.168.1.0/24
Found device: 192.168.1.1
Found device: 192.168.1.100
Found device: 192.168.1.101

NETWORK SCAN RESULTS - 3 devices found
Network: 192.168.1.0/24
Router: 192.168.1.1
================================================================================
IP Address      Device Type     OS           Hostname             MAC Address        Ports
--------------- --------------- ------------ -------------------- ------------------ ----------
🌐 192.168.1.1   Router          Router OS    router.local         aa:bb:cc:dd:ee:ff  80,443
   192.168.1.100 Windows PC      Windows      DESKTOP-ABC123       11:22:33:44:55:66  135,139,445
   192.168.1.101 Android Device  Android      android-phone        77:88:99:aa:bb:cc  
```

## File Structure

- **`main.py`**: Main entry point and user interface
- **`network_scanner.py`**: Core scanning functionality
- **`network_device.py`**: Device data model
- **`network_utils.py`**: Network utility functions (ping, hostname lookup, etc.)
- **`device_identifier.py`**: Device type and OS identification logic
- **`network_mapper.py`**: Visual network mapping functionality
- **`requirements.txt`**: Optional Python dependencies

## Requirements

- **Python 3.7+**
- **Windows/Linux/macOS** (tested on Windows)
- **Network access** to scan local subnet

### Optional Dependencies

Install with `pip install -r requirements.txt`:

- **python-nmap**: For advanced port scanning
- **scapy**: For enhanced network analysis  
- **matplotlib**: For creating visual network maps
- **networkx**: For network topology analysis

## Troubleshooting

### No devices found
- Run as administrator/root for better network access
- Check if Windows Firewall is blocking ping
- Verify your network configuration
- Try manual network configuration when prompted

### Permission errors
- On Windows: Run Command Prompt as Administrator
- On Linux/Mac: Use `sudo python main.py`

### Import errors
- The basic scanner works without optional dependencies
- Install packages individually: `pip install python-nmap matplotlib`

## Security Notes

- This tool only scans your local network
- It uses standard network protocols (ping, TCP connections)
- No intrusive scanning or exploitation attempts
- Respects network security and firewall settings

## Customization

You can modify the scanning behavior by editing:

- **Port lists** in `network_scanner.py`
- **Device identification rules** in `device_identifier.py`  
- **Visual styling** in `network_mapper.py`
- **Known test devices** in the `test_known_devices()` method

## Example Use Cases

- **Home network mapping**: See all devices on your home WiFi
- **IT network auditing**: Quick inventory of network devices
- **Security assessment**: Identify unknown devices
- **Network troubleshooting**: Verify device connectivity and services
