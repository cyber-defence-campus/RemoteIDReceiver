import logging

from scapy.layers.dot11 import Dot11Beacon, Dot11EltVendorSpecific
from scapy.packet import Packet

from info_handler import save_drone_info
from parser_handler import DefaultHandler, DjiHandler, AsdStanHandler
from parsers import Parser

handler = AsdStanHandler(DjiHandler(DefaultHandler(None)))
home_locations = {}


def filter_frames(packet: Packet) -> None:
    """
    Method to filter Wi-Fi frames. Only frames containing a vendor specific element will not be filtered out
    directly. After the first filter a second one is applied which checks if an OUI of the vendor specific elements
    belongs to a format of an implemented handler. If not, it will be dismissed and the next Wi-Fi frame passes through
    the same filter logic.

    Args:
        packet (Packet): Wi-Fi frame.
    """
    #if packet.haslayer(Dot11Beacon):  # Monitor 802.11 beacon traffic
    if packet.haslayer(Dot11EltVendorSpecific):  # check vendor specific ID -> 221
        vendor_spec: Dot11EltVendorSpecific = packet.getlayer(Dot11EltVendorSpecific)
        while vendor_spec:
            layer_oui = Parser.dec2hex(vendor_spec.oui)
            if handler.is_drone(layer_oui):
                # parse header
                remote_id = handler.parse(vendor_spec.info, layer_oui)
                if remote_id:
                    serial = remote_id.serial_number
                    logging.info(f"Parsed Remote ID with serial number for: {serial}")

                    remote_id.add_home_loc(home_locations)
                    logging.info(f"Remote ID: {remote_id}")

                    save_drone_info(remote_id)
                break
            else:
                vendor_spec: Dot11EltVendorSpecific = vendor_spec.payload.getlayer(Dot11EltVendorSpecific)
                continue
