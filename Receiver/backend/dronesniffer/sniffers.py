import logging
import os
from threading import Thread, Event
from scapy.layers.dot11 import Dot11Elt,Dot11EltVendorSpecific
from scapy.sendrecv import AsyncSniffer
from scapy.config import conf
from scapy.packet import Packet
from typing import Callable 

__all__ = ["SniffManager"]

#from lte.lte_sniffer import lte_sniffer

LOG = logging.getLogger(__name__)


def switch_dev_mode(device: str, mode: str) -> bool:
    """
    Changes modes of a device/interface.

    Args:
        device (str): Device/interface that should be changed.
        mode (str): Interface mode, either "monitor" or "managed".

    Returns:
        bool: True if change has succeeded, False otherwise
    """
    if not (mode == "monitor" or mode == "managed"):
        raise ValueError(f"Only modes 'monitor' and 'managed' are supported, not '{mode}'")

    try:
        os.system(f"ip link set {device} down")
        os.system(f"iwconfig {device} mode {mode}")
        os.system(f"ip link set {device} up")
        return True
    except:
        # switch failed, return false
        return False


class WiFiInterfaceSniffer:
    """
    Sniffs Wi-Fi interfaces and forwards packets to handlers.
    """

    def __init__(self, interface: str, on_packet_received: Callable[[Packet], None]) -> None:
        """
        Args:
            interface (str): The Wi-Fi device/interface to sniff on.
            on_packet_received (Callable[[Packet], None]): Callback function to process received packets.
        """
        self.interface = interface
        self.on_packet_received = on_packet_received
        self.sniffer = AsyncSniffer(
            iface=interface,
            prn=on_packet_received
        )

    def start(self) -> bool:
        """
        Sets the interface into monitoring mode and starts sniffing for packets on it.

        Returns:
            bool: True when the sniffing has succeeded, False otherwise.
        """
        logging.info(f"Setting interface '{self.interface}' into monitor mode...")
        success = switch_dev_mode(self.interface, "monitor")

        if success:
            logging.info(f"Starting sniffer on interface '{self.interface}'...")
            self.sniffer.start()
            logging.info(f"Sniffer on interface '{self.interface}' started")
        else:
            logging.info(f"Failed to set interface '{self.interface}' into monitor mode")

        return success

    def stop(self) -> None:
        """
        Stop all sniffing efforts on that interface and set it back to managed mode.
        """
        logging.info(f"Stopping sniffer on interface '{self.interface}'...")
        self.sniffer.stop()
        logging.info(f"Sniffer on interface '{self.interface}' stopped")

        logging.info(f"Setting interface '{self.interface}' into managed mode...")
        switch_dev_mode(self.interface, "managed")


class WiFiFileSniffer:
    """
    Parses a pcap file and forwards the parsed packets to the handler.
    """

    def __init__(self, filename: str, on_packet_received: Callable[[Packet], None]) -> None:
        """
        Args:
            filename (str): The filename of the file to be read and parsed.
            on_packet_received (Callable[[Packet], None]): Callback function to process received packets.
        """
        self.filename = filename
        self.on_packet_received = on_packet_received
        self.sniffer = AsyncSniffer(
            offline=filename,
            prn=on_packet_received
        )

    def start(self) -> bool:
        """
        Reads the file and parses its content.

        Returns:
            bool: Always succeeds and returns True.
        """
        logging.info(f"Starting to parse file {self.filename}")
        self.sniffer.start()
        return True

    def stop(self) -> None:
        """
        Stops all sniffing efforts.
        """
        logging.info(f"Stop parsing file {self.filename}")
        self.sniffer.stop()

'''
class LteFileSniffer:
    """
    Parses a file containing LTE data and forwards the parsed packets to the handler.
    """

    def __init__(self, filename: str = None) -> None:
        """
        Args:
            filename (str): The filename of the file to be read and parsed.
        """
        self.filename = filename
        self.stop_event = Event()
        self.sniffer = Thread(target=lte_sniffer, args=(self.stop_event, filename,), daemon=True)

    def start(self) -> bool:
        """
        Reads the file and parses its content.

        Returns:
            bool: Always succeeds and returns True.
        """
        logging.info(f"Starting to parse LTE file {self.filename}")
        self.sniffer.start()
        return True

    def stop(self) -> None:
        """
        Stops all sniffing efforts.
        """
        logging.info(f"Stop parsing file {self.filename}")
        self.stop_event.set()
        self.sniffer.join()
'''

class SniffManager:
    """
    Managed all different kinds of sniffers.
    Can start/stop new/existing sniffers.
    """

    def __init__(self, on_packet_received: Callable[[Packet], None]) -> None:
        """
        Args:
            on_packet_received (Callable[[Packet], None]): Callback function to process received packets.
        """
        self.sniffers = {}
        self.file_sniffers = []
        self.on_packet_received = on_packet_received

    def start(self, interface: str) -> bool:
        """
        Starts a new WiFiInterfaceSniffer on that interface
        First stops the sniffer if one for that interface already exists.

        Args:
            interface (str): Device/interface to sniff on.

        Returns:
            bool: True when the sniffing started successfully, False otherwise.
        """
        # remove existing sniffer for that interface
        self.stop(interface)
        LOG.info(f"Starting sniffer for interface {interface}...")
        sniffer = WiFiInterfaceSniffer(interface, self.on_packet_received)
        success = sniffer.start()
        if success:
            LOG.info(f"Sniffer for interface {interface} started")
            self.sniffers[interface] = sniffer
        else:
            LOG.warning(f"Failed to start sniffer for interface {interface}")
        return success

    def stop(self, interface: str) -> None:
        """
        Stops the WiFiInterfaceSniffer for that interface IF it exists.

        Args:
            interface (str): The interface to stop the sniffing on.
        """
        if interface in self.sniffers:
            sniffer = self.sniffers[interface]
            sniffer.stop()
            del self.sniffers[interface]

    def set_sniffing_interfaces(self, interfaces: list[str]) -> None:
        """
        Sets the WiFiInterfaceSniffers up for the provided list of interfaces.
        Stops other interfaces and starts new ones if necessary.
        The outcome is that only the provided interfaces are sniffed on.

        Args:
            interfaces (list[str]): List of interfaces we want to sniff on.
        """
        LOG.info(f"Setting sniffing interfaces to {interfaces}...")
        # add new ones
        for interface in interfaces:
            if interface not in self.sniffers:
                self.start(interface)

        # remove old ones
        for interface in self.sniffers.copy():  # requires copy to avoid modification during iteration
            if interface not in interfaces:
                self.stop(interface)

    def parse_file(self, filename: str, lte: bool) -> None:
        """
        Starts a FileSniffer for file with filename. If lte is True a LteFileSniffer is started, otherwise a
        WiFiFileSniffer is started.

        Args:
            filename (str): Filename of the file to be parsed.
            lte (bool): If lte extension is used.
        """
        if lte:
            #logging.info("Creating LTE Sniffer...")
            LOG.info(" LTE Sniffer not ready...")
            #sniffer = LteFileSniffer(filename)
        else:
            LOG.info("Creating Wi-Fi Sniffer...")
            sniffer = WiFiFileSniffer(filename, self.on_packet_received)
        self.file_sniffers.append(sniffer)
        sniffer.start()

    def shutdown(self) -> None:
        """
        Shuts down all sniffers.
        """
        # stop all WiFiInterfaceSniffers
        LOG.info("Stopping all sniffers...")
        for interface in self.sniffers.copy():
            self.stop(interface)

        # stop all WiFiFileSniffers
        for sniffer in self.file_sniffers:
            sniffer.stop()
        self.file_sniffers = []
        LOG.info("All sniffers were stopped successfully.")

