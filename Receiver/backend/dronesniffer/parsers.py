import logging
import math
import struct
from datetime import datetime
from typing import Optional

from scapy.packet import Packet

from exceptions import ParseRemoteIdError
from models import RemoteId, Position
from spoofing_detection import is_spoofed


class Parser:
    """
    Root Parser for a vendor specific packet.
    """
    header_size = 8

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


class AsdStanParser(Parser):
    """
    Class to parse a Wi-Fi packet according to ASD-STAN prEn 4709-002 standard
    (https://asd-stan.org/downloads/pren-4709-002-corr/), which is compliant with the ASTM F3411-19 standard
    (https://www.astm.org/f3411-19.html).
    """
    _msg_type_0_format: str = '<Bc20s3s'
    _msg_type_1_format: str = '<BcBBbiiHHHccHcc'
    _msg_type_4_format: str = '<BciiHBHH8s'

    msg_size: int = 25
    msg_type_one: int = 1
    msg_type_four: int = 4
    oui: str = "FA:0B:BC"

    @staticmethod
    def _bytes_to_bits(byte_list: list[str]) -> list[int]:
        bin_string = ' '.join(f'{x:08b}' for x in byte_list)
        bin_arr = [int(bit) for bit in bin_string]
        bin_arr.reverse()
        return bin_arr

    @staticmethod
    def _to_location(val: int) -> float:
        return val / 10 ** 7

    @staticmethod
    def _check_header(type_byte, check_type) -> None:
        msg_type = struct.unpack("<1s", type_byte)[0]
        if msg_type != check_type:
            msg_type = hex(int.from_bytes(msg_type, 'little'))
            check_type = hex(int.from_bytes(check_type, 'little'))
            raise ParseRemoteIdError(f"Malformed Packet. Expected message type {check_type} but was {msg_type}")

    @staticmethod
    def _parse_type_0(packet: Packet, start: int = None, end: int = None) -> str:
        """
        Method to parse Message Type 0 - Basic ID Message. Defined by ASD-STAN Remote ID Format.

        Args:
            packet (Packet): Wi-Fi packet.
            start (int): Start position in packet (inclusive). defaults to None.
            end (int): End position in packet (exclusive). defaults to None.

        Returns:
            str: Serial number of the Remote ID.
        """
        AsdStanParser._check_header(packet[start:start + 1], b'\x00')
        try:
            (_, _, serial_number, _) = struct.unpack(AsdStanParser._msg_type_0_format, packet[start:end])
        except struct.error as err:
            raise ParseRemoteIdError(f"Unable to unpack message type 0. extra: {err}")
        except ValueError as err:
            raise ParseRemoteIdError(err)

        serial_number = serial_number.decode().rstrip('\x00').strip()
        if not serial_number:
            raise ParseRemoteIdError(f"serial number contains spaces or is wrong formatted")

        return serial_number

    @staticmethod
    def _parse_type_1(packet: Packet, start: int = None, end: int = None) -> tuple:
        """
        Method to parse Message Type 1 - Location/Vector Message. Defined by ASD-STAN Remote ID Format.

        Args:
            packet (Packet): Wi-Fi packet.
            start (int): Start position in packet (inclusive). defaults to None.
            end (int): End position in packet (exclusive). defaults to None.

        Returns:
            tuple: Location/vector information.
        """
        AsdStanParser._check_header(packet[start:start + 1], b'\x10')
        try:
            unpacked_values = struct.unpack(AsdStanParser._msg_type_1_format, packet[start:end])
        except struct.error as err:
            raise ParseRemoteIdError(f"Unable to unpack message type 1. extra: {err}")

        try:
            (version, status_flags, track_dir, speed, v_speed, lat, lng, _, _, height, _, _, timestamp, _,
             _) = unpacked_values
        except ValueError as err:
            raise ParseRemoteIdError(err)

        try:
            status_flags = AsdStanParser._bytes_to_bits(status_flags)
            track_dir = track_dir + 180 if status_flags[1] == 1 else track_dir
            speed = speed * 0.25 if status_flags[0] == 0 else (track_dir * 0.75) + (255 * 0.25)
            v_speed = v_speed * 0.5
            lat = AsdStanParser._to_location(lat)
            lng = AsdStanParser._to_location(lng)
            height = (height * 0.5) - 1000

            min_ = math.floor(timestamp / 600)
            sec = round((timestamp - min_ * 600) / 10)
            now = datetime.now()
            tenth_second = now.minute * 600 + now.second * 10
            if timestamp > tenth_second:
                timestamp = now.replace(hour=now.hour-1, minute=min_, second=sec)
            else:
                timestamp = now.replace(minute=min_, second=sec)
        except Exception as err:
            raise ParseRemoteIdError(f"Error while parsing values for ASD-STAN Remote ID. extra: {err}")

        return lng, lat, height, track_dir, speed, v_speed, timestamp

    @staticmethod
    def _parse_type_4(packet: Packet, start: int, end: int) -> Position:
        """
        Method to parse Message Type 4 - System Message. Defined by ASD-STAN Remote ID Format.

        Args:
            packet (Packet): Wi-Fi packet.
            start (int): Start position in packet (inclusive). defaults to None.
            end (int): End position in packet (exclusive). defaults to None.

        Returns:
            Position: Pilot location information.
        """
        AsdStanParser._check_header(packet[start:start + 1], b'\x40')
        try:
            unpacked_values = struct.unpack(AsdStanParser._msg_type_4_format, packet[start:end])
        except struct.error as err:
            raise ParseRemoteIdError(f"Unable to unpack message type 4. extra: {err}")

        try:
            (_, _, pilot_lat, pilot_lng, _, _, _, _, _) = unpacked_values
        except ValueError as err:
            raise ParseRemoteIdError(err)

        return Position(lng=AsdStanParser._to_location(pilot_lng),
                        lat=AsdStanParser._to_location(pilot_lat),
                        default=True)

    @staticmethod
    def parse_static_msg(packet: Packet, oui: str) -> Optional[RemoteId]:
        """
        Method to parse static messages. Static messages consist of Message Types 0 , 1, 4 and 5 and contain
        information about the unmanned aircraft as well as its location and its pilot's location.

        Args:
            packet (Packet): Wi-Fi packet.
            oui (str): Vendor OUI.

        Returns:
            Optional[RemoteId]: Parsed RemoteId or None.
        """
        """unpack Basic ID Message values"""
        message_start = Parser.header_size
        message_end = Parser.header_size + AsdStanParser.msg_size
        try:
            serial_number = AsdStanParser._parse_type_0(packet, message_start, message_end)
        except ParseRemoteIdError as err:
            logging.warning(err)
            return None

        """unpack Location/Vector Message values"""
        message_start = message_end
        message_end = message_end + AsdStanParser.msg_size
        try:
            (lng, lat, height, track_dir, speed, v_speed, timestamp) = AsdStanParser._parse_type_1(packet,
                                                                                                   message_start,
                                                                                                   message_end)
        except ParseRemoteIdError as err:
            logging.warning(err)
            return None

        try:
            drone_pos = Position(lat=lat, lng=lng)
        except ValueError as err:
            logging.warning(f"Parsing of drone position failed with error: {err}")
            return None

        """unpack System Message values"""
        message_start = message_end
        message_end = message_end + AsdStanParser.msg_size
        try:
            pilot_pos = AsdStanParser._parse_type_4(packet, message_start, message_end)
        except ParseRemoteIdError as err:
            logging.warning(err)
            logging.info("Setting pilot location to None.")
            pilot_pos = Position()

        spoofed = is_spoofed(drone_pos, pilot_pos)

        return RemoteId(lng=lng, lat=lat, height=height, yaw=track_dir, x_speed=speed, y_speed=v_speed,
                        pilot_lat=pilot_pos.lat, pilot_lng=pilot_pos.lng, timestamp=timestamp, oui=oui,
                        uuid=serial_number, serial_number=serial_number, spoofed=spoofed)


class DjiParser(Parser):
    """
    Class to parse a vendor specific element of a Wi-Fi packet and data of a LTE packet according to DJI's proprietary
    solution for the Remote ID. DJI has multiple different versions of their protocol, which will be considered and
    accordingly parsed.
    """
    _version_1_format: str = '<H2s16siiHHhhhhhhiiBB20s'
    protocol_v1: int = 1

    _version_2_format: str = '<H2s16siiHHhhhhQiiiiBB20s'
    protocol_v2: int = 2

    _version_2_lte_format = _version_2_format + 'H'
    lte_max_len = 89

    oui: str = ["60:60:1F", "48:1C:B9", "34:D2:62"]
    spoofed_oui = "26:37:12"

    @staticmethod
    def _to_coordinate(val: int) -> float:
        """ transformation equation:
        (coordinate/180) * PI * 10 ** 7
        """
        return round((val * 180) / math.pi / 10 ** 7)

    @staticmethod
    def _to_angle(val: int) -> float:
        double_val = float(val / 100)

        if double_val == 0:
            return double_val
        elif (double_val < 0) or (double_val >= 180):
            return double_val + 180
        else:
            return double_val % 180

    @staticmethod
    def _get_uuid(byte_value) -> str:
        #.rstrip('\x00').strip()
        return byte_value.decode().rstrip('\x00').strip()

    @staticmethod
    def parse_version_1(packet: Packet, oui: str) -> Optional[RemoteId]:
        """
        Method to parse a vendor specific element of a Wi-Fi packet that contains version 1 of DJI's proprietary
        Remote ID.

        Args:
            packet (Packet): Wi-Fi packet.
            oui (str): Vendor OUI.

        Returns:
            Optional[RemoteId]: Parsed Remote ID or None if parsing not possible.
        """
        try:
            unpacked = struct.unpack(DjiParser._version_1_format, packet[Parser.header_size:])
        except struct.error as err:
            logging.warning(f"Unable to unpack DJI version 1. extra: {err}")
            return None

        try:
            (_, _, serial_number, drone_lon, drone_lat, _, height,
             x_speed, y_speed, _, _, _, yaw, home_lng, home_lat, _, _, uuid) = unpacked
        except ValueError as err:
            logging.warning(err)
            return None

        try:
            pos = Position(lat=DjiParser._to_coordinate(drone_lat), lng=DjiParser._to_coordinate(drone_lon))
        except ValueError as err:
            logging.warning(err)
            return None

        home_pos = Position(lat=DjiParser._to_coordinate(home_lat),
                            lng=DjiParser._to_coordinate(home_lng),
                            default=True)

        spoofed = is_spoofed(pos, home_pos)

        try:
            return RemoteId(lng=pos.lng, lat=pos.lat, height=height / 10, yaw=DjiParser._to_angle(yaw), x_speed=x_speed,
                            y_speed=y_speed, timestamp=datetime.now(), oui=oui, home_lat=home_pos.lat,
                            home_lng=home_pos.lng, uuid=DjiParser._get_uuid(uuid),
                            serial_number=serial_number.decode(), spoofed=spoofed)
        except Exception as err:
            logging.warning(f"Error while parsing values for DJI Remote ID. extra: {err}")
            return None

    @staticmethod
    def parse_version_2(packet: Packet, oui: str) -> Optional[RemoteId]:
        """
        Method to parse a vendor specific element of a Wi-Fi packet that contains version 2 of DJI's proprietary
        Remote ID.

        Args:
            packet (Packet): Wi-Fi packet.
            oui (str): Vendor OUI.

        Returns:
            Optional[RemoteId]: Parsed Remote ID or None if parsing not possible.
        """
        message_start = Parser.header_size
        try:
            unpacked = struct.unpack(DjiParser._version_2_format, packet[message_start:])
        except struct.error as err:
            logging.warning(f"Unable to unpack DJI version 2. extra: {err}")
            return None

        try:
            (_, _, serial_number, lng, lat, _, height, x_speed, y_speed, _, yaw, _, pilot_lat, pilot_lng, home_lng,
             home_lat, _, _, uuid) = unpacked
        except ValueError as err:
            logging.warning(err)
            return None

        try:
            pos = Position(lat=DjiParser._to_coordinate(lat), lng=DjiParser._to_coordinate(lng))
        except ValueError as err:
            logging.warning(f"Parsing of drone position failed with error: {err}")
            return None

        home_pos = Position(lat=DjiParser._to_coordinate(home_lat),
                            lng=DjiParser._to_coordinate(home_lng),
                            default=True)

        pilot_pos = Position(lat=DjiParser._to_coordinate(pilot_lat),
                             lng=DjiParser._to_coordinate(pilot_lng),
                             default=True)

        spoofed = is_spoofed(pos, pilot_pos)

        try:
            return RemoteId(lng=pos.lng, lat=pos.lat, height=height / 10, yaw=DjiParser._to_angle(yaw), x_speed=x_speed,
                            y_speed=y_speed, timestamp=datetime.now(), pilot_lat=pilot_pos.lat, pilot_lng=pilot_pos.lng,
                            oui=oui, home_lng=home_pos.lng, home_lat=home_pos.lat, uuid=DjiParser._get_uuid(uuid),
                            serial_number=serial_number.decode('utf-8').rstrip('\u0000'), spoofed=spoofed)
        except Exception as err:
            logging.warning(f"Error while parsing values for DJI Remote ID. extra: {err}")
            return None

    @staticmethod
    def parse_version_2_lte(packet: Packet, oui: str) -> Optional[RemoteId]:
        """
        Method to parse a vendor specific element of a LTE packet that contains version 2 of DJI's proprietary
        Remote ID.

        Args:
            packet (Packet): LTE packet.
            oui (str): Vendor OUI.

        Returns:
            Optional[RemoteId]: Parsed Remote ID or None if parsing not possible.
        """
        try:
            unpacked = struct.unpack(DjiParser._version_2_format, packet[3:DjiParser.lte_max_len])
        except struct.error as err:
            logging.warning(f"Unable to unpack packet. extra: {err}")
            return None

        try:
            (_, _, serial_number, lng, lat, _, height, x_speed, y_speed, _, yaw,
             _, pilot_lat, pilot_lng, home_lng, home_lat, _, _, uuid) = unpacked
        except ValueError as err:
            logging.warning(err)
            return None

        try:
            pos = Position(lat=DjiParser._to_coordinate(lat), lng=DjiParser._to_coordinate(lng))
        except ValueError as err:
            logging.warning(err)
            return None

        home_pos = Position(lat=DjiParser._to_coordinate(home_lat),
                            lng=DjiParser._to_coordinate(home_lng),
                            default=True)

        pilot_pos = Position(lat=DjiParser._to_coordinate(pilot_lat),
                             lng=DjiParser._to_coordinate(pilot_lng),
                             default=True)

        spoofed = is_spoofed(pos, pilot_pos)

        try:
            return RemoteId(lng=pos.lng, lat=pos.lat, height=height / 10, yaw=DjiParser._to_angle(yaw), x_speed=x_speed,
                            y_speed=y_speed, timestamp=datetime.now(), pilot_lat=pilot_pos.lat,
                            pilot_lng=pilot_pos.lng, oui=oui, home_lng=home_pos.lng, home_lat=home_pos.lat,
                            uuid=DjiParser._get_uuid(uuid),
                            serial_number=serial_number.decode('utf-8').rstrip('\u0000'), spoofed=spoofed)
        except Exception as err:
            logging.warning(f"Error while parsing values for DJI Remote ID. extra: {err}")
            return None
