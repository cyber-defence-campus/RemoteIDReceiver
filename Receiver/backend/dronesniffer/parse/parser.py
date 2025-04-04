from scapy.packet import Packet

import struct
from scapy.packet import Packet
from exceptions import ParseRemoteIdError

class Parser:

    """
    Root Parser for a vendor specific packet.
    """
    header_size = 8
    oui = None

    @staticmethod
    def extract_header(packet: Packet) -> tuple:
        """
        Method to extract the header of a vendor specific element in a Wi-Fi packet. The header consists of three
        bytes representing the OUI, followed by 4 bytes which are vendor specific and therefore their value is
        unknown. And lastly a single byte indicating the version or message type, which can be used to parse the
        RemoteID.

        Args:
            packet (Packet): Wi-Fi packet.

        Returns:
            tuple: Header content (oui, vendor_spec_bytes, version).
        """
        header_format = '<3s4sB'
        try:
            header = struct.unpack(header_format, packet[:Parser.header_size])
            if not header:
                raise ParseRemoteIdError("Empty header detected after successfully unpacking")
            return header
        except struct.error as e:
            raise ParseRemoteIdError(f"Unable to unpack header packet. extra: {e}")

    @staticmethod
    def dec2hex(oui_dec: int) -> str:
        """
        Method to parse the decimal value of the OUI to a readable and formatted hex value of the OUI. The format of
        the OUI is according to IEEE either AB:CD:EF or without colon ABCDEF. This method parsed the OUI to the
        first mentioned format -> AC:CD:EF.

        Args:
            oui_dec (int): Decimal value of OUI.

        Returns:
            str: Formatted OUI.
        """
        max_ = 16777215
        min_ = 0
        if oui_dec < min_ or oui_dec > max_:
            return "00:00:00"
        oui_raw = hex(oui_dec)[2:].zfill(6)  # [2:0] -> to remove '0x' part of hex value
        return f"{oui_raw[0:2]}:{oui_raw[2:4]}:{oui_raw[4:]}".upper()