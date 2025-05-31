# ===== network_dashboard.py =====
import os
import sqlite3
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

from network_monitor import NetworkMonitor
from snort_integration import SnortIntegration

# -------------------------------
# Configure logging for the whole application
# -------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------
# Create Flask + SocketIO app
# -------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# -------------------------------
# Instantiate global monitor & snort objects
# -------------------------------
monitor = NetworkMonitor(db_path="network_monitor.db")
snort = SnortIntegration(snort_log_path="/var/log/snort/alert")

# -------------------------------
# Load devices from scan_results.json on startup
# -------------------------------
def load_devices_from_scan():
    """Load devices from info/scan_results.json into the database."""
    scan_file = Path("info/scan_results.json")
    if not scan_file.exists():
        logger.warning("Scan results file not found: info/scan_results.json")
        return
    
    try:
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        devices = scan_data.get('devices', [])
        if not devices:
            logger.info("No devices found in scan results")
            return
        
        conn = sqlite3.connect(monitor.db_path)
        cursor = conn.cursor()
        
        for device in devices:
            cursor.execute('''
                INSERT OR REPLACE INTO devices (ip, mac, hostname, device_type, os, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                device.get('ip'),
                device.get('mac'),
                device.get('hostname', 'Unknown'),
                device.get('device_type', 'Unknown'),
                device.get('os', 'Unknown'),
                datetime.now()
            ))
        
        conn.commit()
        conn.close()
        logger.info(f"Loaded {len(devices)} devices from scan results")
        
    except Exception as e:
        logger.error(f"Error loading devices from scan results: {e}")

# -------------------------------
# Flask Routes
# -------------------------------

@app.route('/')
def dashboard():
    """Serve the main dashboard HTML."""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """
    Return current network statistics (packet_rate, bandwidth, protocol_stats, top_talkers).
    These values are updated every second by the NetworkMonitor threads.
    """
    return jsonify({
        'packet_rate': monitor.stats['packet_rate'],
        'bandwidth': round(monitor.stats['bandwidth'], 2),
        'protocol_stats': dict(monitor.stats['protocol_stats']),
        'top_talkers': dict(
            sorted(
                monitor.stats['top_talkers'].items(),
                key=lambda x: x[1]['bytes'],
                reverse=True
            )[:10]
        ),
        'monitoring_status': monitor.running
    })

@app.route('/api/alerts')
def get_alerts():
    """
    Fetch recent alerts from the SQLite `alerts` table (last 24 hours).
    Returns up to 100 alerts, sorted by timestamp descending.
    """
    conn = sqlite3.connect(monitor.db_path)
    cursor = conn.cursor()
    yesterday = datetime.now() - timedelta(days=1)

    cursor.execute('''
        SELECT timestamp, severity, signature, src_ip, dst_ip, description
        FROM alerts
        WHERE timestamp > ?
        ORDER BY timestamp DESC
        LIMIT 100
    ''', (yesterday,))
    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            'timestamp': row[0],
            'severity': row[1],
            'signature': row[2],
            'src_ip': row[3],
            'dst_ip': row[4],
            'description': row[5]
        })
    return jsonify(alerts)

@app.route('/api/devices', methods=['POST'])
def update_devices():
    """
    Receive JSON payload with device info from a front-end scan,
    insert/replace rows in the `devices` table. Expected format:
      { "devices": [ { "ip": "...", "mac": "...", "hostname": "...",
                       "device_type": "...", "os": "..." }, ... ] }
    """
    devices_data = request.get_json()
    conn = sqlite3.connect(monitor.db_path)
    cursor = conn.cursor()

    for device in devices_data.get('devices', []):
        cursor.execute('''
            INSERT OR REPLACE INTO devices (ip, mac, hostname, device_type, os, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            device.get('ip'),
            device.get('mac'),
            device.get('hostname'),
            device.get('device_type'),
            device.get('os'),
            datetime.now()
        ))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/devices')
def get_devices():
    """
    Return all known devices from the `devices` table, ordered by last_seen descending.
    """
    conn = sqlite3.connect(monitor.db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT ip, mac, hostname, device_type, os, last_seen FROM devices ORDER BY last_seen DESC')
    rows = cursor.fetchall()
    conn.close()

    devices = []
    for row in rows:
        devices.append({
            'ip': row[0],
            'mac': row[1],
            'hostname': row[2],
            'device_type': row[3],
            'os': row[4],
            'last_seen': row[5]
        })
    return jsonify(devices)

# -------------------------------
# SocketIO Event Handlers
# -------------------------------

@socketio.on('connect')
def handle_connect():
    emit('status', {'msg': 'Connected to Network Monitor'})

@socketio.on('start_monitoring')
def handle_start_monitoring(data):
    """
    Front-end can trigger this event (via: socket.emit('start_monitoring', { interface: 'eth0' }))
    to begin packet capture on the specified interface.
    """
    interface = data.get('interface', r'\Device\NPF_{E4D75602-5B8B-4765-8BED-488B492886BA}')
    monitor.start_monitoring(interface)
    emit('monitoring_started', {'interface': interface})
    emit('status', {'msg': f'Monitoring started on {interface}'})

@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    """Stop packet capture and metric threads."""
    monitor.stop_monitoring()
    emit('monitoring_stopped')
    emit('status', {'msg': 'Monitoring stopped'})

# -------------------------------
# HTML Template Generation
# -------------------------------

def create_html_template():
    """
    Generate `templates/dashboard.html` (if it doesn't exist) with all the
    necessary CSS, JS, and HTML layout for the dashboard.
    """
    template_dir = Path('templates')
    template_dir.mkdir(exist_ok=True)

    html_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>🛡️ Network Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        /* Basic reset and container styling */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; color: #333;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; color: white; margin-bottom: 30px; }
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px; margin-bottom: 30px;
        }
        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px; padding: 20px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .metric { text-align: center; padding: 15px; }
        .metric-value {
            font-size: 2.5em; font-weight: bold; color: #667eea; display: block;
        }
        .metric-label { font-size: 0.9em; color: #666; margin-top: 5px; }
        .chart-container { position: relative; height: 300px; margin-top: 20px; }
        .alerts-list { max-height: 400px; overflow-y: auto; }
        .alert-item {
            display: flex; justify-content: space-between;
            align-items: center; padding: 10px; margin: 5px 0;
            border-radius: 6px; border-left: 4px solid;
        }
        .alert-high { border-left-color: #e74c3c; background: #fdf2f2; }
        .alert-medium { border-left-color: #f39c12; background: #fdf8f2; }
        .alert-low { border-left-color: #27ae60; background: #f2fdf7; }
        .controls { margin-bottom: 20px; text-align: center; }
        .btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white; border: none; padding: 10px 20px;
            border-radius: 6px; cursor: pointer; margin: 0 10px;
            font-size: 16px; transition: transform 0.2s;
        }
        .btn:hover:not(:disabled) { transform: translateY(-2px); }
        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }
        .btn.active {
            background: linear-gradient(45deg, #27ae60, #2ecc71);
        }
        .status {
            position: fixed; top: 20px; right: 20px;
            padding: 10px 20px; border-radius: 6px;
            background: #27ae60; color: white; display: none;
        }
        .top-talkers { list-style: none; }
        .top-talkers li {
            display: flex; justify-content: space-between;
            padding: 8px 0; border-bottom: 1px solid #eee;
        }
        table {
            width: 100%; border-collapse: collapse; margin-top: 15px;
        }
        th, td {
            padding: 10px; text-align: left; border-bottom: 1px solid #ddd;
        }
        th { background: #f8f9fa; font-weight: 600; }
        .monitoring-status {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }
        .monitoring-active {
            background: #27ae60;
            color: white;
        }
        .monitoring-inactive {
            background: #e74c3c;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Network Security Dashboard</h1>
            <p>Real-time network monitoring and intrusion detection</p>
            <span id="monitoringStatus" class="monitoring-status monitoring-inactive">STOPPED</span>
        </div>

        <div class="controls">
            <button id="startBtn" class="btn" onclick="startMonitoring()">Start Monitoring</button>
            <button id="stopBtn" class="btn" onclick="stopMonitoring()" disabled>Stop Monitoring</button>
            <select id="interface">
                <option value="\\Device\\NPF_{E4D75602-5B8B-4765-8BED-488B492886BA}">Wi-Fi Interface</option>
                <option value="eth0">eth0</option>
                <option value="wlan0">wlan0</option>
                <option value="any">any</option>
            </select>
        </div>

        <div id="status" class="status"></div>

        <div class="dashboard-grid">
            <div class="card">
                <h3>📊 Real-Time Traffic</h3>
                <div class="metric">
                    <span id="packetRate" class="metric-value">0</span>
                    <div class="metric-label">Packets/sec</div>
                </div>
                <div class="metric">
                    <span id="bandwidth" class="metric-value">0.0</span>
                    <div class="metric-label">Mbps</div>
                </div>
            </div>

            <div class="card">
                <h3>🔥 Top Talkers</h3>
                <ul id="topTalkers" class="top-talkers">
                    <li>No data available</li>
                </ul>
            </div>

            <div class="card">
                <h3>📈 Protocol Distribution</h3>
                <div class="chart-container">
                    <canvas id="protocolChart"></canvas>
                </div>
            </div>

            <div class="card">
                <h3>🚨 Security Alerts</h3>
                <div id="alertsContainer" class="alerts-list">
                    <div class="alert-item alert-low">
                        <span>No alerts detected</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>💻 Network Devices</h3>
            <table id="devicesTable">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Hostname</th>
                        <th>Device Type</th>
                        <th>OS</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody id="devicesTableBody">
                    <tr>
                        <td colspan="6">Loading devices...</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // Initialize Socket.IO
        const socket = io();

        // Chart.js instance placeholder
        let protocolChart;
        let isMonitoring = false;

        function initCharts() {
            const ctx = document.getElementById('protocolChart').getContext('2d');
            protocolChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
                            '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }

        function updateMonitoringUI(monitoring) {
            isMonitoring = monitoring;
            const startBtn = document.getElementById('startBtn');
            const stopBtn = document.getElementById('stopBtn');
            const statusEl = document.getElementById('monitoringStatus');
            
            startBtn.disabled = monitoring;
            stopBtn.disabled = !monitoring;
            
            if (monitoring) {
                statusEl.textContent = 'ACTIVE';
                statusEl.className = 'monitoring-status monitoring-active';
            } else {
                statusEl.textContent = 'STOPPED';
                statusEl.className = 'monitoring-status monitoring-inactive';
            }
        }

        function updateDashboard() {
            // Fetch stats
            fetch('/api/stats')
                .then(res => res.json())
                .then(data => {
                    document.getElementById('packetRate').textContent = data.packet_rate;
                    document.getElementById('bandwidth').textContent = data.bandwidth;

                    // Update monitoring status
                    updateMonitoringUI(data.monitoring_status);

                    // Top talkers
                    const topTalkersEl = document.getElementById('topTalkers');
                    if (Object.keys(data.top_talkers).length === 0) {
                        topTalkersEl.innerHTML = '<li>No data available</li>';
                    } else {
                        topTalkersEl.innerHTML = '';
                        for (const [ip, stats] of Object.entries(data.top_talkers)) {
                            const li = document.createElement('li');
                            li.innerHTML = `
                                <span>${ip}</span>
                                <span>${(stats.bytes / 1024).toFixed(1)} KB</span>
                            `;
                            topTalkersEl.appendChild(li);
                        }
                    }

                    // Protocol chart
                    if (Object.keys(data.protocol_stats).length > 0) {
                        protocolChart.data.labels = Object.keys(data.protocol_stats);
                        protocolChart.data.datasets[0].data = Object.values(data.protocol_stats);
                        protocolChart.update();
                    }
                });

            // Fetch alerts
            fetch('/api/alerts')
                .then(res => res.json())
                .then(alerts => {
                    const alertsContainer = document.getElementById('alertsContainer');
                    alertsContainer.innerHTML = '';
                    if (alerts.length === 0) {
                        alertsContainer.innerHTML =
                            '<div class="alert-item alert-low"><span>No alerts detected</span></div>';
                        return;
                    }
                    alerts.slice(0, 10).forEach(alert => {
                        const alertEl = document.createElement('div');
                        alertEl.className = `alert-item alert-${alert.severity.toLowerCase()}`;
                        alertEl.innerHTML = `
                            <div>
                                <strong>${alert.signature}</strong><br>
                                <small>${alert.src_ip} → ${alert.dst_ip}</small>
                            </div>
                            <small>${new Date(alert.timestamp).toLocaleTimeString()}</small>
                        `;
                        alertsContainer.appendChild(alertEl);
                    });
                });

            // Fetch devices
            fetch('/api/devices')
                .then(res => res.json())
                .then(devices => {
                    const tbody = document.getElementById('devicesTableBody');
                    tbody.innerHTML = '';
                    if (devices.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6">No devices found</td></tr>';
                        return;
                    }
                    devices.forEach(dev => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${dev.ip}</td>
                            <td>${dev.mac}</td>
                            <td>${dev.hostname || 'Unknown'}</td>
                            <td>${dev.device_type}</td>
                            <td>${dev.os}</td>
                            <td>${new Date(dev.last_seen).toLocaleString()}</td>
                        `;
                        tbody.appendChild(row);
                    });
                });
        }

        function startMonitoring() {
            const iface = document.getElementById('interface').value;
            socket.emit('start_monitoring', { interface: iface });
        }

        function stopMonitoring() {
            socket.emit('stop_monitoring');
        }

        // Socket event handlers
        socket.on('status', data => {
            const statusEl = document.getElementById('status');
            statusEl.textContent = data.msg;
            statusEl.style.display = 'block';
            setTimeout(() => { statusEl.style.display = 'none'; }, 3000);
        });

        socket.on('monitoring_started', data => {
            updateMonitoringUI(true);
        });

        socket.on('monitoring_stopped', data => {
            updateMonitoringUI(false);
        });

        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            updateDashboard();
            setInterval(updateDashboard, 2000);
        });
    </script>
</body>
</html>
'''

    # Write out to templates/dashboard.html
    with open(template_dir / 'dashboard.html', 'w', encoding='utf-8') as f:
        f.write(html_content)

def stop_monitoring():
    """Stop the network monitoring threads."""
    monitor.stop_monitoring()

# -------------------------------
# Entry point
# -------------------------------
if __name__ == '__main__':
    # Ensure the HTML exists
    create_html_template()
    
    # Load devices from scan results on startup
    load_devices_from_scan()

    logger.info("Starting Network Security Dashboard...")
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        monitor.stop_monitoring()
    except Exception as e:
        logger.error(f"Error starting application: {e}")