#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This script sends packets from a pcapng file to a specified network interface.
It requires root privileges to run and checks if the specified interface is in monitor mode.
If the interface is not in monitor mode, it provides instructions on how to set it.
The script uses Scapy to send packets and tqdm to display a progress bar.
"""
import argparse
import os
import sys
import subprocess
from scapy.all import sendp, PcapReader
from tqdm import tqdm

# Initialize argument parser
parser = argparse.ArgumentParser(
    description="Send pcapng packets to a specified interface."
)
# Define command-line arguments
parser.add_argument(
    "-i", "--interface", required=True, help="Network interface to send packets on"
)
parser.add_argument(
    "-f",
    "--file",
    default="parrot_anafi4_real.pcapng",
    help="Input pcapng file (default: parrot_anafi4_real.pcapng)",
)
# Parse command-line arguments
args = parser.parse_args()

# Check if the script is run as root, which is required for sending packets
if os.geteuid() != 0:
    print("This script must be run as root in order to send packets.")
    print("Please run the script with sudo.")
    sys.exit(1)


# Function to check if the network interface is in monitor mode
def is_monitor_mode(interface):
    try:
        # Run iw command to get interface information
        result = subprocess.run(
            ["iw", "dev", interface, "info"], capture_output=True, text=True, check=True
        )
        # Check if "type monitor" is in the output, indicating monitor mode
        return "type monitor" in result.stdout
    except subprocess.CalledProcessError as e:
        # Handle errors during iw command execution
        print(f"Error checking interface {interface} status: {e}")
        return False
    except FileNotFoundError:
        # Handle case where iw command is not found
        print("iw command not found. Please ensure iw is installed.")
        return False


# Check if the specified interface is in monitor mode before proceeding
if not is_monitor_mode(args.interface):
    print(f"Interface {args.interface} is not in monitor mode.")
    print("Please set it to monitor mode first. You can try running these commands:")
    print(f"sudo ip link set {args.interface} down")
    print(f"sudo iw dev {args.interface} set type monitor")
    print(f"sudo ip link set {args.interface} up")
    print(
        "If the issues persist, https://www.aircrack-ng.org/doku.php?id=airmon-ng provides a tool to set the interface to monitor mode."
    )
    sys.exit(1)

print(
    f"Starting to read and send packets from {args.file} on interface {args.interface}..."
)
# Get total packet count for the progress bar
total_packets = sum(1 for _ in PcapReader(args.file))
print(f"Found {total_packets} packets to send...")

# Open the pcapng file using PcapReader
with PcapReader(args.file) as pcap_reader:
    # Iterate over packets and send them, showing progress with tqdm
    for pkt in tqdm(pcap_reader, total=total_packets, desc="Sending packets"):
        # Send the packet on the specified interface using Scapy
        sendp(pkt, iface=args.interface, verbose=False)

print(f"Finished sending {total_packets} packets from {args.file}.")
