# ===== network_monitor.py =====
import sqlite3
import threading
import time
from datetime import datetime
from collections import defaultdict
import logging

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP

logger = logging.getLogger(__name__)

class NetworkMonitor:
    """
    Handles real-time packet capture (via Scapy), updates protocol/device stats,
    detects simple intrusions, and stores packets/alerts in SQLite.
    """
    def __init__(self, db_path="network_monitor.db"):
        self.db_path = db_path
        self.running = False
        self.packet_buffer = []
        self.stats = {
            'packet_rate': 0,
            'bandwidth': 0.0,
            'top_talkers': {},
            'protocol_stats': defaultdict(int),
            'alerts': []
        }
        self.setup_database()

    def setup_database(self):
        """Initialize SQLite database with tables for packets, alerts, and devices."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create packets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                size INTEGER,
                src_port INTEGER,
                dst_port INTEGER
            )
        ''')

        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                severity TEXT,
                signature TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                description TEXT
            )
        ''')

        # Create devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                hostname TEXT,
                device_type TEXT,
                os TEXT,
                last_seen DATETIME
            )
        ''')

        conn.commit()
        conn.close()

    def packet_handler(self, packet):
        """
        Callback for Scapy.sniff. Extracts IP/TCP/UDP fields, updates in-memory stats,
        checks for suspicious ports, and buffers packet info for DB insertion.
        """
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto_num = packet[IP].proto
            size = len(packet)

            # Map numeric protocol → name
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol_name = protocol_map.get(proto_num, f'Proto-{proto_num}')

            src_port = dst_port = 0
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol_name = 'TCP'

                # Override if well-known ports (HTTP/HTTPS/SSH/DNS)
                if 80 in (dst_port, src_port):
                    protocol_name = 'HTTP'
                elif 443 in (dst_port, src_port):
                    protocol_name = 'HTTPS'
                elif 22 in (dst_port, src_port):
                    protocol_name = 'SSH'
                elif 53 in (dst_port, src_port):
                    protocol_name = 'DNS'

            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol_name = 'UDP'
                if 53 in (dst_port, src_port):
                    protocol_name = 'DNS'
                elif dst_port in (67, 68):
                    protocol_name = 'DHCP'

            # Build packet_info dict
            packet_info = {
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol_name,
                'size': size,
                'src_port': src_port,
                'dst_port': dst_port
            }

            # Buffer and process
            self.packet_buffer.append(packet_info)
            self.update_stats(packet_info)
            self.check_intrusion(packet_info)

    def update_stats(self, packet_info):
        """Update protocol counts and per-source 'top talkers' (bytes + packet count)."""
        proto = packet_info['protocol']
        self.stats['protocol_stats'][proto] += 1

        src = packet_info['src_ip']
        if src not in self.stats['top_talkers']:
            self.stats['top_talkers'][src] = {'bytes': 0, 'packets': 0}

        self.stats['top_talkers'][src]['bytes'] += packet_info['size']
        self.stats['top_talkers'][src]['packets'] += 1

    def check_intrusion(self, packet_info):
        """
        Simple intrusion logic:
         - (Placeholder) Port-scan detection logic
         - Detect traffic on known 'suspicious' ports → generate HIGH alerts
        """
        # Placeholder: port-scan logic could be expanded here
        suspicious_ports = [1234, 4444, 5555, 6666, 31337]
        dst_port = packet_info['dst_port']
        src_port = packet_info['src_port']

        if dst_port in suspicious_ports or src_port in suspicious_ports:
            alert = {
                'timestamp': datetime.now(),
                'severity': 'HIGH',
                'signature': 'Suspicious Port Activity',
                'src_ip': packet_info['src_ip'],
                'dst_ip': packet_info['dst_ip'],
                'description': f"Traffic on suspicious port {dst_port or src_port}"
            }
            self.stats['alerts'].append(alert)
            self.store_alert(alert)

    def store_packet(self, packet_info):
        """Insert a captured packet record into the `packets` table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, size, src_port, dst_port)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_info['timestamp'],
            packet_info['src_ip'],
            packet_info['dst_ip'],
            packet_info['protocol'],
            packet_info['size'],
            packet_info['src_port'],
            packet_info['dst_port']
        ))
        conn.commit()
        conn.close()

    def store_alert(self, alert):
        """Insert a generated alert into the `alerts` table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, severity, signature, src_ip, dst_ip, description)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert['timestamp'],
            alert['severity'],
            alert['signature'],
            alert['src_ip'],
            alert['dst_ip'],
            alert['description']
        ))
        conn.commit()
        conn.close()

    def calculate_metrics(self):
        """
        Every second:
         - Compute packets/sec over the last 1s
         - Compute bandwidth (Mbps) over last 1s
         - Trim packet_buffer older than 60s
        """
        current_time = time.time()
        one_second_ago = current_time - 1

        recent_packets = [
            p for p in self.packet_buffer
            if (current_time - p['timestamp'].timestamp()) < 1
        ]
        self.stats['packet_rate'] = len(recent_packets)

        recent_bytes = sum(p['size'] for p in recent_packets)
        # Convert to Megabits/sec
        self.stats['bandwidth'] = (recent_bytes * 8) / (1024 * 1024)

        # Remove packets older than 60s from buffer
        self.packet_buffer = [
            p for p in self.packet_buffer
            if (current_time - p['timestamp'].timestamp()) < 60
        ]

    def start_monitoring(self, interface='eth0'):
        """
        Launch two daemon threads:
         1. scapy.sniff(...) with packet_handler callback
         2. metrics_loop (invokes calculate_metrics every second)
        """
        self.running = True
        logger.info(f"Starting packet capture on interface: {interface}")

        def capture_packets():
            try:
                scapy.sniff(
                    iface=interface,
                    prn=self.packet_handler,
                    stop_filter=lambda _: not self.running
                )
            except Exception as e:
                logger.error(f"Error in packet capture: {e}")

        capture_thread = threading.Thread(target=capture_packets, daemon=True)
        capture_thread.start()

        def metrics_loop():
            while self.running:
                self.calculate_metrics()
                time.sleep(1)

        metrics_thread = threading.Thread(target=metrics_loop, daemon=True)
        metrics_thread.start()

    def stop_monitoring(self):
        """Signal threads to stop capturing and reporting metrics."""
        self.running = False
