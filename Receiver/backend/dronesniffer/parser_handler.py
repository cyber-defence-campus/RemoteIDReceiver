import logging
from abc import abstractmethod
from typing import Optional

from scapy.packet import Packet

from exceptions import ParseRemoteIdError
from models import RemoteId
from parsers import DjiParser, AsdStanParser


class Handler(object):
    """
    Interface for the handler class used in the chain of responsibility patter.
    """
    def __init__(self, nxt):
        self._nxt = nxt

    @abstractmethod
    def accepts(self, oui: str) -> bool:
        """
        Method to check if this handler is responsible to handle a vendor specific element of a Wi-Fi packet. This
        method is used by the parse method.

        Args:
            oui (str): Vendor OUI.

        Returns:
            bool: True, if it is handled by this handler else, False.
        """
        raise NotImplementedError

    def parse(self, packet: Packet, oui: str) -> Optional[RemoteId]:
        """
        Method to handle/parse a vendor specific element of a Wi-Fi packet.

        Args:
            packet (Packet): Wi-Fi packet.
            oui (str): vendor OUI.

        Returns:
            Optional[RemoteId]: Parsed RemoteId or None if parsing not possible.
        """
        return self._nxt.parse(packet, oui)

    def is_drone(self, oui: str) -> bool:
        """
        Checks if an OUI is handled by a handler. This method can be used to decide if a vendor specific element of
        a Wi-Fi packet will be handled by a handler in the chain without handling it. It's more like a filter before
        actually handling the packets.

        Args:
            oui (str): Vendor OUI.

        Returns:
            bool: True, if the OUI is handled by this handler else, False.
        """
        return self._nxt.is_drone(oui)


class DefaultHandler(Handler):
    """
    Represents the default handler. Marking the end of the chain of responsibility.
    """
    def accepts(self, oui: str) -> bool:
        return True

    def parse(self, packet, oui: str) -> Optional[RemoteId]:
        return None

    def is_drone(self, oui: str) -> bool:
        return False


class DjiHandler(Handler):
    """
    Represents the handler for the DJI proprietary Remote ID format (drone flight info).
    """
    def accepts(self, oui: str) -> bool:
        return oui in DjiParser.oui

    def parse(self, packet, oui: str) -> Optional[RemoteId]:
        handled = self.accepts(oui)

        if not handled:
            return super().parse(packet, oui)

        try:
            (_, _, msg_type) = DjiParser.extract_header(packet)
        except ParseRemoteIdError as err:
            logging.warning(err)
            return None

        if msg_type == DjiParser.protocol_v1:
            return DjiParser.parse_version_1(packet, oui)
        elif msg_type == DjiParser.protocol_v2:
            return DjiParser.parse_version_2(packet, oui)
        else:
            logging.info("Unknown DJI protocol version detected")
            return None

    def is_drone(self, oui: str) -> bool:
        return True if self.accepts(oui) else super().is_drone(oui)


class AsdStanHandler(Handler):
    """
    Represents the handler for the ASD-STAN Remote ID format.
    """

    def accepts(self, oui: str) -> bool:
        return oui == AsdStanParser.oui

    def parse(self, packet, oui: str) -> Optional[RemoteId]:
        accepted = self.accepts(oui)

        if not accepted:
            return super().parse(packet, oui)

        try:
            (_, _, msg_type) = AsdStanParser.extract_header(packet)
        except ParseRemoteIdError as err:
            logging.warning(err)
            return None

        if msg_type == AsdStanParser.msg_type_four:
            return AsdStanParser.parse_static_msg(packet, oui)
        else:
            logging.info("Unknown ASD-STAN message type detected")
            return None

    def is_drone(self, oui: str) -> bool:
        return True if self.accepts(oui) else super().is_drone(oui)
