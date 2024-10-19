# Starcode Network Scanner

**Starcode Network Scanner** is a simple yet powerful network scanning tool that identifies devices connected to your local network using ARP requests. This tool is developed in Python and utilizes the Scapy library for packet manipulation and the `manuf` library for MAC address lookups.

## Features

- **Identify Devices**: Scans the local network to identify devices along with their IP and MAC addresses.
- **Vendor Lookup**: Fetches the vendor name associated with the MAC address using multiple sources.
- **Logging**: Logs the scanning process and results to a file for future reference.
- **CSV Export**: Saves the scan results to a CSV file for easy sharing and analysis.
- **Interactive Output**: Displays scan results in a formatted manner directly in the terminal.

## Requirements

- Python 3.x
- Required libraries:
  - `scapy`
  - `manuf`
  - `requests`
  - `pandas`
  - `psutil`

## Installation

### Clone the repository

```bash
git clone https://github.com/starcode-id/starprobe.git
cd starprobe
pip install -r requirements.txt
sudo python3 main.py

