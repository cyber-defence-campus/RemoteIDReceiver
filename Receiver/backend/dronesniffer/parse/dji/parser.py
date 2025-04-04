

import logging
import math
import struct
from datetime import datetime
from typing import Optional

from scapy.packet import Packet

from exceptions import ParseRemoteIdError
from models import RemoteId, Position
from spoofing_detection import is_spoofed
from parse.parser import Parser

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

    spoofed_oui = "26:37:12"
    oui: list[str] = ["60:60:1F", "48:1C:B9", "34:D2:62", spoofed_oui]

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
