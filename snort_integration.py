# ===== snort_integration.py =====
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SnortIntegration:
    """
    Parses a Snort alert log file (e.g. /var/log/snort/alert) line by line,
    returning any newly appended alerts as dicts.
    """
    def __init__(self, snort_log_path="/var/log/snort/alert"):
        self.snort_log_path = snort_log_path
        self.last_position = 0

    def parse_snort_alerts(self):
        """
        Opens the Snort log file, seeks to the last read position,
        reads new lines, updates self.last_position, and returns a list of parsed alerts.
        """
        alerts = []
        if not os.path.exists(self.snort_log_path):
            logger.warning(f"Snort log file not found: {self.snort_log_path}")
            return alerts

        try:
            with open(self.snort_log_path, 'r') as f:
                f.seek(self.last_position)
                lines = f.readlines()
                self.last_position = f.tell()

                for line in lines:
                    parsed = self.parse_snort_line(line)
                    if parsed:
                        alerts.append(parsed)
        except Exception as e:
            logger.error(f"Error parsing Snort alerts: {e}")

        return alerts

    def parse_snort_line(self, line):
        """
        Simplified parsing of a single Snort alert line. Adjust this
        logic to your Snort output format if needed.
        """
        try:
            parts = line.strip().split()
            if len(parts) < 5:
                return None

            return {
                'timestamp': datetime.now(),
                'severity': 'MEDIUM',  # ➔ In a real setup, map from Snort priorities
                'signature': ' '.join(parts[2:5]),
                'src_ip': parts[0] if '->' in line else 'unknown',
                'dst_ip': parts[2] if '->' in line else 'unknown',
                'description': line.strip()
            }
        except Exception:
            return None
