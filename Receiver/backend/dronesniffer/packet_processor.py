import logging

from scapy.layers.dot11 import Dot11EltVendorSpecific
from scapy.packet import Packet

from info_handler import save_messages
from parse.parser import Parser
from parse.parser_service import parser
from map.mapping_service import mapper
from time_buffer import TimeBuffer

LOG = logging.getLogger(__name__)

# Limit DB writes to a certain interval
# This is to prevent flooding the database with too many writes
# this is especially important because the target hardware is a raspberry pi with an sd-card as storage.
time_buffer = TimeBuffer(interval_seconds=1, on_flush=save_messages)

def process_packet(packet: Packet) -> None:
    """
    Method to filter Wi-Fi frames. Only frames containing a vendor specific element will not be filtered out
    directly. After the first filter a second one is applied which checks if an OUI of the vendor specific elements
    belongs to a format of an implemented handler. If not, it will be dismissed and the next Wi-Fi frame passes through
    the same filter logic.

    Args:
        packet (Packet): Wi-Fi frame.
    """
    vendor_spec: Dot11EltVendorSpecific = _get_vendor_specific(packet)
    while vendor_spec:

        # Check if the packet was sent by a drone
        layer_oui = Parser.dec2hex(vendor_spec.oui)
        if parser.is_supported_protocol(layer_oui):
            
            # Parse the drone packet
            parsed_message = parser.from_wifi(vendor_spec.info, layer_oui)
            if parsed_message:
                LOG.debug(f"Parsed message: {parsed_message}")

                # Map the parsed message to the DB model
                mac_from = packet.addr2
                db_models = mapper.to_db_models(parsed_message, mac_from)
                LOG.debug(f"DB models: {db_models}")
                
                # Save the message to the database
                for model in db_models:
                    time_buffer.add(model)
            break
        else:
            vendor_spec: Dot11EltVendorSpecific = vendor_spec.payload.getlayer(Dot11EltVendorSpecific)


def _get_vendor_specific(packet: Packet) -> Dot11EltVendorSpecific:
    """
    Get the vendor specific layer from the packet.

    Args:
        packet (Packet): Wi-Fi frame.

    Returns:
        Dot11EltVendorSpecific: Vendor specific layer.
    """
    if packet.haslayer(Dot11EltVendorSpecific):
        return packet.getlayer(Dot11EltVendorSpecific)
    else:
        return None