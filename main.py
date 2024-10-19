from scapy.all import ARP, Ether, srp, conf
from manuf import manuf
from functools import lru_cache
import argparse
import logging
import requests
import psutil
import shutil
import os
import socket
import ipaddress
import textwrap
# Define ANSI escape codes for colors
RED = "\033[91m"
RESET = "\033[0m"
def setup_logging():
    # Configure logging after checking for sudo privileges
    logging.basicConfig(
        filename='network_scan.log',
        filemode='a',  # append mode
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner menggunakan ARP.")
    parser.add_argument(
        "-o", "--output", help="Nama file output untuk menyimpan hasil (opsional)"
    )
    args = parser.parse_args()
    return args
def in_sudo_mode():
    """Check if the script is running with sudo privileges."""
    if os.getuid() != 0:
        print(f'{RED}[*] Try Running This Program With Sudo.')
        exit()
def print_banner():
    """Display a banner in the terminal."""
    terminal_size = shutil.get_terminal_size((80,20))
    width = terminal_size.columns
    name = textwrap.dedent(f"""
         ▗▄▄▖▗▄▄▄▖▗▄▖ ▗▄▄▖ ▗▄▄▖ ▗▄▄▖  ▗▄▖ ▗▄▄▖ ▗▄▄▄▖
        ▐▌     █ ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌   
         ▝▀▚▖  █ ▐▛▀▜▌▐▛▀▚▖▐▛▀▘ ▐▛▀▚▖▐▌ ▐▌▐▛▀▚▖▐▛▀▀▘
        ▗▄▄▞▘  █ ▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌ ▐▌▝▚▄▞▘▐▙▄▞▘▐▙▄▄▖
        +========================================+
        | Created by: StarCode                   |
        | GitHub: https://github.com/starcode-id |
        +========================================+
    """)
    centered_name = '\n'.join([line.center(width) for line in name.splitlines()])
    print(centered_name)
@lru_cache(maxsize=1000)
def get_mac_vendor_from_macvendors(mac_address):
    # try to fetch vendor name from macvendors.com
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200 and response.text.strip():
            return response.text.strip()
        logging.warning(f'vendor not found on macvendors.com for {mac_address}')
    except requests.RequestException as e:
        logging.error(f'error fetching vendor from macvendors.com {e}')
    except KeyboardInterrupt:
        exit()
    return None
@lru_cache(maxsize=1000)
def get_mac_vendor_from_maclookup(mac_address):
    # try to fetch vendor name from maclookup.app
    try:
        url = f"https://api.maclookup.app/v2/macs/{mac_address}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'company' in data and data['company']:
                return data['company']
        logging.warning(f'vendor not found on maclookup.com for {mac_address}')
    except requests.RequestException as e:
        logging.error(f'error fetching vendor from maclookup.app {e}')
    except KeyboardInterrupt:
        exit()
    return None

def get_mac_vendor_from_manuf(mac_address):
    # fallback to manuf library for local vendor lookup
    try:
        manuf_parser = manuf.MacParser()
        vendor_name = manuf_parser.get_manuf(mac_address)
        if vendor_name:
            return vendor_name
        logging.warning(f'no vendor found in manuf for {mac_address}')
    except Exception as e:
        logging.error(f'error with manuf library {e}')
    return None
def get_mac_vendor(mac_address):
    """Fetch the vendor name usingg multiple source with fallback"""
    vendors = []
    for func in (get_mac_vendor_from_maclookup,
                 get_mac_vendor_from_macvendors,
                 get_mac_vendor_from_manuf
                 ):
        vendor = func(mac_address)
        if vendor:
            vendors.append(vendor)
    if vendors :
        return vendors[0]
    logging.warning(f"Vendor for {mac_address} could not be determined.")
    return 'Unknown'

def scan_network(ip_range, iface):
    """Scan the network for devices."""
    logging.info(f'memulai scanning pada jaringan {ip_range} di interface {iface}')
    # Create ARP request and encapsulate in Ethernet frame    
    arp_request = ARP(pdst=ip_range)
    ether_frame = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether_frame / arp_request
    
    # Send the packet and catch responses
    try:
        result = srp(packet, iface=iface, timeout=1, verbose=False)[0]
    except PermissionError:
        logging.error('akses di tolak. jalankan script dengan hak akses root/admin.')
        return []
    except Exception as e:
        logging.error(f'terjadi error selama scanning {e}')
        return []
    except KeyboardInterrupt:
        exit()
    devices = []
    
    for sent, recived in result:
        mac = recived.hwsrc
        vendor = get_mac_vendor(mac)
        ip = recived.psrc
        Len = len(ip)
        
        new_devices = {
            'IP Address' : ip,
            'MAC Address' : mac,
            'Len': Len,
            'Vendor' : vendor,
        }
        # Check for duplicates based on IP address
        if new_devices['IP Address'] not in [d['IP Address'] for d in devices]:
            devices.append(new_devices)
            
    return devices
    

def get_active_interface_and_subnet():
    """Detect the active network interface."""
    interfaces = psutil.net_if_addrs()
    for interface, addresses in interfaces.items():
        for addr in addresses:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                ip = ipaddress.ip_interface(f"{addr.address}/{addr.netmask}")
                logging.info(f'Active interface: {interface} - Subnet: {ip.network}')
                return interface, str(ip.network)
    raise Exception('tidak ada interface jaringan aktif ditemukan')
def calculate_column_widths(num_colums):
    # calculate the widths of columns on terminal size and number of columns
    terminal_size = shutil.get_terminal_size((80,20))
    width = terminal_size.columns
    
    column_widths = [width // num_colums] * num_colums
    total_width = sum(column_widths)
    extra_space = width - total_width
    if extra_space > 0:
        column_widths[0] += extra_space
    return column_widths
def save_to_csv(df, filename='network_scan.csv'):
    """Save the scan results to a CSV file."""
    try:
        df.to_csv(filename, index=False)
        logging.info(f'hasil scan disimpan ke {filename}')
    except Exception as e:
        logging.error(f'gagal menyimpan file {e}')
        print(f"[*] Failed to save results to {filename}. Error: {e}")
    except KeyboardInterrupt:
        exit()
def display_output(devices, displayed_ips):
    """Display the scanned devices in a formatted manner."""
    if devices:
        logging.info(f'{len(devices)} perangkat ditemukan')
        num_columns = 5
        column_widths = calculate_column_widths(num_columns)
        for device in devices:
            if device['IP Address'] not in displayed_ips:
                print(f"{device['IP Address']:<{column_widths[0]}} | {device['MAC Address']:<{column_widths[1]}} | {device['Len']:<{column_widths[3]}} | {device['Vendor']:<{column_widths[4]}}")
                displayed_ips.add(device['IP Address'])

def main():
    in_sudo_mode()
    setup_logging()
    args = get_arguments()
    print_banner()
    
    # Mendeteksi interface aktif
    try:
        interface,subnet = get_active_interface_and_subnet()
    except Exception as e:
        logging.error(e)
        exit()
    display_ips = set()
    print("Scanning network... Press Ctrl+C to stop.")
    # Print the header using the calculated column widths
    num_columns = 5
    column_widths = calculate_column_widths(num_columns)
    print("-" * sum(column_widths)) 
    print(f"{'IP Address':<{column_widths[0]}} | {'MAC Address':<{column_widths[1]}} | {'Len':<{column_widths[3]}} | {'Vendor':<{column_widths[4]}}")
    print("-" * sum(column_widths))  # Separator line
    all_devices = []
    try:
        while True:
            # Jalankan scanning dan tampilkan hasil
            devices = scan_network(subnet, interface)
            display_output(devices, display_ips)
            all_devices.extend(devices)

        if args.output:
            save_to_csv(df, args.output)
    except KeyboardInterrupt:
        exit()
        print('\nexit...')

if __name__ == '__main__':
    main()