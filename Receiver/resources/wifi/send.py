import argparse
import os
import sys
import subprocess
from scapy.all import sendp, PcapReader
from tqdm import tqdm

parser = argparse.ArgumentParser(
    description="Send pcapng packets to a specified interface."
)
parser.add_argument(
    "-i", "--interface", required=True, help="Network interface to send packets on"
)
parser.add_argument(
    "-f",
    "--file",
    default="parrot_anafi4_real.pcapng",
    help="Input pcapng file (default: parrot_anafi4_real.pcapng)",
)
args = parser.parse_args()

if os.geteuid() != 0:
    print("This script must be run as root in order to send packets.")
    print("Please run the script with sudo.")
    sys.exit(1)


def is_monitor_mode(interface):
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"], capture_output=True, text=True, check=True
        )
        return "type monitor" in result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error checking interface {interface} status: {e}")
        return False
    except FileNotFoundError:
        print("iw command not found. Please ensure iw is installed.")
        return False


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
# Get total packet count first
total_packets = sum(1 for _ in PcapReader(args.file))
print(f"Found {total_packets} packets to send...")

with PcapReader(args.file) as pcap_reader:
    for pkt in tqdm(pcap_reader, total=total_packets, desc="Sending packets"):
        sendp(pkt, iface=args.interface, verbose=False)

print(f"Finished sending {total_packets} packets from {args.file}.")
