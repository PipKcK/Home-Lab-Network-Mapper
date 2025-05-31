# 🛡️ Home Lab Network Scanner & Mapper

A comprehensive Python-based network scanning and monitoring tool designed for home lab environments. This tool provides device discovery, real-time network monitoring, and a web-based security dashboard.

## 🚀 Features

### Network Scanning
- **Device Discovery**: Automatically discovers devices on your local network
- **Enhanced Identification**: Identifies device types (PC, Smartphone, Router) and operating systems
- **Port Scanning**: Detects open ports and services on discovered devices
- **Nmap Integration**: Optional advanced scanning capabilities with python-nmap

### Real-Time Monitoring
- **Live Packet Capture**: Real-time network traffic analysis using Scapy
- **Protocol Statistics**: Track HTTP, HTTPS, DNS, TCP, UDP traffic
- **Bandwidth Monitoring**: Monitor network usage and top talkers
- **Intrusion Detection**: Basic security alerts for suspicious activity

### Web Dashboard
- **Interactive Interface**: Flask-based web dashboard with real-time updates
- **Visual Analytics**: Charts and graphs for network statistics
- **Device Management**: View and manage discovered network devices
- **Security Alerts**: Display and track security events

## 🎯 Supported Devices

Currently recognizes and identifies:
- **PCs**: Windows, Linux, macOS computers
- **Smartphones**: Android and iOS devices
- **Routers**: Network gateway devices
- **Servers**: Web servers, Linux servers
- **Printers**: Network-connected printers

## 🔧 Requirements

### System Requirements
- **Operating System**: Windows (primary support)
- **Network**: LAN network on 192.168.x.x range
- **Connection**: Wi-Fi connection recommended
- **Python**: Python 3.7 or higher

### Dependencies
Install required packages:
```bash
pip install -r requirements.txt
```

#### Core Dependencies
- `python-nmap>=1.6.0` - Advanced network scanning
- `scapy>=2.4.5` - Packet capture and analysis
- `flask` - Web dashboard framework
- `flask-socketio` - Real-time web updates
- `psutil` - System monitoring
- `matplotlib>=3.5.0` - Network visualization (optional)
- `networkx>=2.8.0` - Network analysis (optional)

## 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd network-scanner-mapper
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Nmap** (optional but recommended):
   - Download from [nmap.org](https://nmap.org/download.html)
   - Add to system PATH

4. **Configure known devices** (optional):
   ```bash
   cp known_devices.ini.example known_devices.ini
   # Edit known_devices.ini with your device information
   ```

## 🎮 Usage

### Basic Network Scan

Run the main script:
```bash
python main_script.py
```

The tool will:
1. Auto-detect your network range and router IP
2. Scan for active devices
3. Identify device types and operating systems
4. Display results in a formatted table
5. Export results to JSON

### Interactive Menu Options

After scanning, choose from:
1. **Rescan network** - Perform a fresh network scan
2. **Test known devices** - Verify specific device identification
3. **Create network map** - Generate visual network topology
4. **Export results** - Save scan data to JSON file
5. **Start Dashboard** - Launch web-based monitoring interface
6. **Exit** - Close the application

### Web Dashboard

Launch the dashboard:
```bash
python network_dashboard.py
```

Or use option 5 from the main menu.

Access at: `http://localhost:5000`

Dashboard features:
- Real-time traffic monitoring
- Protocol distribution charts
- Security alerts
- Device inventory
- Top talkers analysis

## 📁 Project Structure

```
├── main_script.py           # Main application entry point
├── network_scanner.py       # Core scanning functionality
├── network_device.py        # Device data model
├── device_identifier.py     # Device type identification logic
├── network_utils.py         # Network utility functions
├── network_dashboard.py     # Web dashboard application
├── network_monitor.py       # Real-time monitoring engine
├── network_mapper.py        # Network visualization (in development)
├── snort_integration.py     # Snort IDS integration
├── requirements.txt         # Python dependencies
└── templates/
    └── dashboard.html       # Web dashboard template
```

## 🔧 Configuration

### Network Configuration
The tool auto-detects network settings, but you can manually configure:

```python
# Manual network configuration in main_script.py
router_ip = "192.168.0.1"
network_range = "192.168.0.0/24"
```

### Known Devices Configuration
Create `known_devices.ini` to test specific devices:

```ini
[192.168.0.100]
expected_type = PC
expected_os = Windows

[192.168.0.101]
expected_type = Smartphone
expected_os = Android
```

### Port Configuration
Modify common ports in `network_scanner.py`:

```python
self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 8080]
```

## 📊 Output Files

- `info/scan_results.json` - Complete scan results
- `network_monitor.db` - SQLite database for monitoring data
- `network_map.png` - Visual network map (when implemented)
- `flask_dashboard.log` - Dashboard application logs

## 🔒 Security Features

### Intrusion Detection
- Monitors for suspicious port activity
- Tracks unusual traffic patterns
- Generates security alerts
- Logs all security events

### Monitoring Capabilities
- Real-time packet analysis
- Protocol-based traffic classification
- Bandwidth usage tracking
- Top talkers identification

## ⚠️ Limitations

- **Platform**: Primarily designed for Windows environments
- **Network**: Optimized for 192.168.x.x LAN networks
- **Connection**: Best performance with Wi-Fi connections
- **Device Types**: Limited to PC, Smartphone, and Router identification
- **Interface**: Wi-Fi interface is currently hardcoded (see TODO)

## 🛠️ Troubleshooting

### Common Issues

1. **No devices found**:
   - Check firewall settings
   - Run as administrator
   - Verify network connectivity

2. **Nmap not working**:
   - Install Nmap separately
   - Add to system PATH
   - Falls back to basic scanning automatically

3. **Dashboard not accessible**:
   - Check if port 5000 is available
   - Verify Flask installation
   - Check firewall rules

4. **Packet capture fails**:
   - Run as administrator
   - Check network interface name
   - Verify Scapy installation

## 🔮 TODO

### High Priority
- [ ] **Dynamic Wi-Fi Interface Detection**: Implement automatic interface detection using `tshark -D` command
- [ ] **Enhanced Dashboard Features**: 
  - [ ] Historical data visualization
  - [ ] Advanced filtering options
  - [ ] Export capabilities for charts
  - [ ] Real-time alerting system
- [ ] **Comprehensive Testing**: 
  - [ ] Test on different network configurations
  - [ ] Validate device identification accuracy
  - [ ] Performance testing with larger networks

### Medium Priority
- [ ] Cross-platform support (Linux, macOS)
- [ ] Advanced device fingerprinting
- [ ] Network topology visualization
- [ ] API endpoints for external integration
- [ ] Configuration file management
- [ ] Docker containerization

### Low Priority
- [ ] Machine learning-based device classification
- [ ] Integration with external threat intelligence
- [ ] Mobile app companion
- [ ] Cloud synchronization capabilities

## 📝 License

This project is intended for educational and home lab use. Please ensure compliance with local network monitoring regulations.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📞 Support

For questions and support, please open an issue in the project repository.

---

**Note**: This tool is designed for legitimate network administration and security monitoring in environments you own or have explicit permission to monitor.