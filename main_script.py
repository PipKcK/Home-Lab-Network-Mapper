#!/usr/bin/env python3
"""
Network Scanner & Mapper - Main Script
A comprehensive tool to scan local network, identify devices, and create a network map.
"""

import ipaddress
from network_scanner import NetworkScanner
from network_mapper import NetworkMapper
import subprocess
import signal

flask_process = None

def start_dashboard_background():
    global flask_process
    log_file = open("flask_dashboard.log", "w")  # Keep reference to avoid garbage collection

    flask_process = subprocess.Popen(
        ["python", "network_dashboard.py"],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP  # Windows only
    )


def main():
    """Main function to run the network scanner"""
    print("Home Lab: Network Scanner & Mapper")
    print("==================================")
    print()
    
    scanner = NetworkScanner()
    
    # Get network info first
    scanner.get_network_info()
    
    # If auto-detection failed or seems wrong, offer manual configuration
    if not scanner.network_range or "192.168.1.0" in scanner.network_range:
        print(f"Auto-detected network: {scanner.network_range}")
        print(f"Auto-detected router: {scanner.router_ip}")
        
        manual = input("\nDoes this look correct? (y/n): ").strip().lower()
        if manual == 'n':
            print("\nPlease enter your network information:")
            router_ip = input("Router IP (e.g., 192.168.0.1): ").strip()
            if router_ip:
                scanner.router_ip = router_ip
                # Derive network from router IP
                network = ipaddress.IPv4Network(f"{router_ip}/24", strict=False)
                scanner.network_range = str(network)
                print(f"Using network: {scanner.network_range}")
    
    # Scan network
    print("\nStarting network scan...")
    devices = scanner.scan_network(use_nmap=True)
    
    if devices:
        # Print results
        scanner.print_results()
        
        # Export results
        scanner.export_results()
        
        print(f"\nScan completed! Found {len(devices)} devices.")
        
        # Show additional options
        while True:
            print("\nOptions:")
            print("1. Rescan network")
            print("2. Test known devices")
            print("3. Create new network map")
            print("4. Export results")
            print("5. Start Dashboard")
            print("6. Exit")
            
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == '1':
                print("Rescanning network...")
                scanner.scan_network()
                scanner.print_results()
            elif choice == '2':
                print("Testing known devices...")
                scanner.test_known_devices()
                scanner.print_results()
            elif choice == '3':
                print("Creating network map...")
                try:
                    filename = input("Enter filename for map (default: network_map.png): ").strip()
                    if not filename:
                        filename = "network_map.png"
                    network_range = scanner.network_range if scanner.network_range is not None else ""
                    router_ip = scanner.router_ip if scanner.router_ip is not None else ""
                    mapper = NetworkMapper(scanner.devices, network_range, router_ip)
                    mapper.create_network_map(filename)
                except Exception as e:
                    print(f"Could not create network map: {e}")
            elif choice == '4':
                filename = input("Enter filename for export (default: network_scan_results.json): ").strip()
                if not filename:
                    filename = "network_scan_results.json"
                scanner.export_results(filename)
            elif choice == '5':
                print("Starting Dashboard...")
                # Placeholder for dashboard functionality
                # python network_dashboard.py
                #subprocess.Popen(['start', 'cmd', '/k', 'python network_dashboard.py'], shell=True)

                start_dashboard_background()
                print("Flask dashboard started in the background.")
                print("You can access it at http://localhost:5000")

            elif choice == '6':
                if flask_process:
                    print("Terminating Flask dashboard...")
                    flask_process.send_signal(signal.CTRL_BREAK_EVENT)
                    flask_process.wait()
                break
            else:
                print("Invalid choice. Please try again.")
    else:
        print("No devices found. This could be due to:")
        print("1. Firewall blocking ping/scan attempts")
        print("2. Network isolation/security settings")  
        print("3. Incorrect network configuration")
        print("\nTry running as administrator or check your network settings.")

if __name__ == "__main__":
    main()
