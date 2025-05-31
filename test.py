import subprocess
import re

def get_wifi_interface():
    try:
        # Run tshark -D to list all interfaces
        result = subprocess.run(['tshark', '-D'], capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')

        for line in lines:
            # Look for line containing '(Wi-Fi)' or similar
            if '(Wi-Fi)' in line:
                # Extract the device name before the first space
                match = re.match(r'\d+\.\s+([^\s]+)', line)
                if match:
                    return match.group(1)
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        print("Defaulting to 'wlan0' if available.")

    return 'wlan0'

# Example usage
wifi_iface = get_wifi_interface()
print(f"Detected Wi-Fi interface: {wifi_iface}")
