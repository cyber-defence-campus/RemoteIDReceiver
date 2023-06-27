import math
import struct

import pytest

from parsers import AsdStanParser, DjiParser

operator_id = [
    ("test_serial_number12", "test_serial_number12"),
    ("test_serial_", "test_serial_"),
    ("test Serial 12", "test Serial 12"),
    ("+2`ä-,°", "+2`ä-,°"),
]

valid_drone_loc = [
    (12, -20, 12, -20),
    (0, -20, 0, -20),
    (90, -20, 90, -20),
    (89, -20, 89, -20),
    (-90, -20, -90, -20),
    (-89, -20, -89, -20),
    (22, 0, 22, 0),
    (22, 180, 22, 180),
    (22, 179, 22, 179),
    (22, -179, 22, -179),
    (22, -180, 22, -180),
]

invalid_drone_loc = [
    (-92, 12),
    (91, 12),
    (12, -181),
    (12, 181),
]

pilot_loc = [
    (-91, -20, None, -20),
    (91, -20, None, -20),
    (22, -181, 22, None),
    (22, 181, 22, None),
]

class TestAsdStanParser:
    def setup_packet(self,
                     serial: str = "test_serial",
                     lat: int = 473763399,
                     lng: int = 85312562,
                     p_lat: int = 473764499,
                     p_lng: int = 85312262,
                     all_types: bool = True,
                     ) -> bytes:
        rotation = 90
        serial_byte = struct.pack("<20s", serial.encode())
        msg_type_0 = b''.join([b'\x00\x12', serial_byte, b'\x00\x00\x00'])

        ew_dir_byte = struct.pack("<B", 32)  # a standard value to set E/W direction segment bit
        direction_byte = struct.pack("<B", rotation)  # rotation of drone in degrees
        lat_byte = struct.pack("<i", lat)  # drone lat, lat of Kasernenareal in Zurich
        lng_byte = struct.pack("<i", lng)  # drone lng, lng of Kasernenareal in Zurich
        tenth_seconds_byte = struct.pack("<H", 5060)  # tenth of seconds since hour
        msg_type_1 = b''.join(
            [b'\x10', ew_dir_byte, direction_byte, b'\x00\x00', lat_byte, lng_byte, b'\x00\x00\x00\x00\xd0\x07\x00\x00',
             tenth_seconds_byte, b'\x00\x00'])

        msg_type_5 = b'\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        header = b'\x0d\x5d\xf0\x19\x04'  # oui: fa:0b:bc (ASD-STAN)

        if not all_types:
            return b''.join([header, msg_type_0, msg_type_1, msg_type_5])

        pilot_lat_byte = struct.pack("<i", p_lat)  # pilot lat, close to drone lat
        pilot_lng_byte = struct.pack("<i", p_lng)  # pilot lng, close to drone lng
        msg_type_4 = b''.join([b'\x40\x05', pilot_lat_byte, pilot_lng_byte,
                               b'\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00'])

        return b''.join([header, msg_type_0, msg_type_1, msg_type_4, msg_type_5])

    def test_asd_parser(self):
        # Arrange
        oui = "FA:0B:BC"
        serial_number="test_serial_number12"
        vendor_spec_data = self.setup_packet(serial=serial_number)

        # Act
        result = AsdStanParser.parse_static_msg(b'\xfa\x0b\xbc' + vendor_spec_data, oui)

        # Assert
        assert result
        assert result.serial_number == serial_number
        assert result.lat == 47.3763399
        assert result.lng == 8.5312562
        assert result.yaw == 90
        assert result.oui == oui

    @pytest.mark.parametrize("input_serial,expected_serial", operator_id)
    def test_valid_serial_number(self, input_serial, expected_serial):
        # Arrange
        oui = "FA:0B:BC"
        vendor_spec_data = self.setup_packet(serial=input_serial)

        # Act
        result = AsdStanParser.parse_static_msg(b'\xfa\x0b\xbc' + vendor_spec_data, oui)

        # Assert
        assert result
        assert result.serial_number == expected_serial
        assert result.lat == 47.3763399
        assert result.lng == 8.5312562
        assert result.yaw == 90
        assert result.oui == oui

    @pytest.mark.parametrize("serial_number", ["", "  "])
    def test_invalid_serial_number(self, serial_number, caplog):
        # Arrange
        oui = "FA:0B:BC"
        vendor_spec_data = self.setup_packet(serial=serial_number)

        # Act
        result = AsdStanParser.parse_static_msg(b'\xfa\x0b\xbc' + vendor_spec_data, oui)

        # Assert
        assert not result
        assert "serial number contains spaces or is wrong formatted" in caplog.text

    @pytest.mark.parametrize("lat,lng,expected_lat,expected_lng", valid_drone_loc)
    def test_valid_drone_location(self, lat, lng, expected_lat, expected_lng):
        # Arrange
        oui = "FA:0B:BC"
        vendor_spec_data = self.setup_packet(lat=lat * 10**7, lng=lng * 10**7)

        # Act
        result = AsdStanParser.parse_static_msg(b'\xfa\x0b\xbc' + vendor_spec_data, oui)

        # Assert
        assert result
        assert result.lat == expected_lat
        assert result.lng == expected_lng

    @pytest.mark.parametrize("lat,lng", invalid_drone_loc)
    def test_invalid_drone_location(self, lat, lng, caplog):
        # Arrange
        oui = "FA:0B:BC"
        vendor_spec_data = self.setup_packet(lat=lat * 10**7, lng=lng * 10**7)

        # Act
        result = AsdStanParser.parse_static_msg(b'\xfa\x0b\xbc' + vendor_spec_data, oui)

        # Assert
        assert not result
        assert "Parsing of drone position failed with error" in caplog.text
        assert ". Setting " not in caplog.text

    @pytest.mark.parametrize("lat,lng,expected_lat,expected_lng", pilot_loc)
    def test_pilot_location(self, lat, lng, expected_lat, expected_lng, caplog):
        # Arrange
        oui = "FA:0B:BC"
        vendor_spec_data = self.setup_packet(p_lat=lat * 10**7, p_lng=lng * 10**7)

        # Act
        result = AsdStanParser.parse_static_msg(b'\xfa\x0b\xbc' + vendor_spec_data, oui)

        # Assert
        assert result
        assert result.pilot_lat == expected_lat
        assert result.pilot_lng == expected_lng
        assert "must be between" in caplog.text
        assert "to None" in caplog.text

    def test_set_default_pilot(self, caplog):
        # Arrange
        oui = "FA:0B:BC"
        vendor_spec_data = self.setup_packet(all_types=False)

        # Act
        result = AsdStanParser.parse_static_msg(b'\xfa\x0b\xbc' + vendor_spec_data, oui)

        # Assert
        assert result
        assert result.pilot_lat == None
        assert result.pilot_lng == None

    def test_malformed_packet(self, caplog):
        # Arrange
        oui = "FA:0B:BC"
        header = b'\x0d\x5d\xf0\x19\x04'  # oui: fa:0b:bc (ASD-STAN)
        serial_byte = struct.pack("<20s", "test_serial".encode())
        msg_type_0 = b''.join([b'\x00\x12', serial_byte, b'\x00\x00\x00'])
        msg_type_5 = b'\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        vendor_spec_data = b''.join([header, msg_type_0, msg_type_5])

        # Act
        result = AsdStanParser.parse_static_msg(b'\xfa\x0b\xbc' + vendor_spec_data, oui)

        # Assert
        assert not result
        assert "Malformed Packet. Expected message type 0x10 but was 0x50" in caplog.text


class TestDjiV2Parser:
    def setup_packet(self,
                     serial: str = "test_serial",
                     lat: int = 8268731,
                     lng: int = 1488985,
                     p_lat: int = 8336478,
                     p_lng: int = 1488985,
                     angle: int = 90,
                     uuid: str = "test_uuid",
                     ) -> bytes:
        v_spec = b'\x58\x62\x13'
        p_type = b'\x10\x02'
        seq_nr = b'\x4d\x06'
        state_inf = b'\x33\x1f'
        serial_byte = struct.pack("<16s", serial.encode())
        lng_byte = struct.pack("<i", lng)  # drone lng, lng of Kasernenareal in Zurich
        lat_byte = struct.pack("<i", lat)  # drone lat, lat of Kasernenareal in Zurich
        met = b'\x1f\x00\x33\x00\xb8\x0b\x78\x05\x34\x08'
        angle = struct.pack("<h", angle)
        timest = b'\x43\x33\x49\x3d\x00\x00\x00\x00'
        pilot_lat_byte = struct.pack("<i", p_lat)  # pilot lat, close to drone lat
        pilot_lng_byte = struct.pack("<i", p_lng)  # pilot lng, close to drone lng
        home_lat_byte = struct.pack("<i", lat)  # home lat, starting lat of flight
        home_lng_byte = struct.pack("<i", lng)  # home lng, starting lng of flight
        model = b'\x47'
        uuid_byte = struct.pack('<20s', uuid.encode())
        uuid_len = len(uuid).to_bytes(1, 'little')
        return b''.join([v_spec, p_type, seq_nr, state_inf, serial_byte, lng_byte, lat_byte, met, angle, timest,
                         pilot_lat_byte, pilot_lng_byte, home_lng_byte, home_lat_byte, model, uuid_len, uuid_byte])

    @pytest.mark.parametrize("uuid,expected_uuid", operator_id)
    def test_valid_uuid(self, uuid, expected_uuid):
        # Arrange
        oui = "60:60:1F"
        vendor_spec_data = self.setup_packet(uuid=uuid)

        # Act
        result = DjiParser.parse_version_2(b'\x60\x60\x1f' + vendor_spec_data, oui)

        # Assert
        assert result
        assert result.uuid == expected_uuid

    @pytest.mark.parametrize("serial", ["test_serial_numb", "test_serial_", "test Serial 12", "+2`ä-,°"])
    def test_serial_number(self, serial):
        # Arrange
        oui = "60:60:1F"
        vendor_spec_data = self.setup_packet(serial=serial)

        # Act
        result = DjiParser.parse_version_2(b'\x60\x60\x1f' + vendor_spec_data, oui)

        # Assert
        assert result
        assert result.serial_number == serial

    @pytest.mark.parametrize("lat,lng,expected_lat,expected_lng", valid_drone_loc)
    def test_valid_drone_location(self, lat, lng,expected_lat,expected_lng):
        # Arrange
        oui = "60:60:1F"
        lat = round(lat / 180 * math.pi * 10**7)
        lng = round(lng / 180 * math.pi * 10**7)
        vendor_spec_data = self.setup_packet(lat=lat, lng=lng)

        # Act
        result = DjiParser.parse_version_2(b'\x60\x60\x1f' + vendor_spec_data, oui)

        # Assert
        assert result
        assert round(result.lat, 4) == round(expected_lat, 4)
        assert round(result.lng, 4) == round(expected_lng, 4)

    @pytest.mark.parametrize("lat,lng", invalid_drone_loc)
    def test_invalid_drone_location(self, lat, lng, caplog):
        # Arrange
        oui = "60:60:1F"
        lat = round(lat / 180 * math.pi * 10**7)
        lng = round(lng / 180 * math.pi * 10**7)
        vendor_spec_data = self.setup_packet(lat=lat, lng=lng)

        # Act
        result = DjiParser.parse_version_2(b'\x60\x60\x1f' + vendor_spec_data, oui)

        # Assert
        assert not result
        assert "Parsing of drone position failed with error" in caplog.text
        assert ". Setting " not in caplog.text

    @pytest.mark.parametrize("lat,lng,expected_lat,expected_lng", pilot_loc)
    def test_pilot_location(self, lat, lng, expected_lat, expected_lng, caplog):
        # Arrange
        oui = "60:60:1F"
        lat = round(lat / 180 * math.pi * 10 ** 7)
        lng = round(lng / 180 * math.pi * 10 ** 7)
        vendor_spec_data = self.setup_packet(p_lat=lat, p_lng=lng)

        # Act
        result = DjiParser.parse_version_2(b'\xfa\x0b\xbc' + vendor_spec_data, oui)

        # Assert
        assert result
        assert not result.pilot_lat or round(result.pilot_lat, 4) == round(expected_lat, 4)
        assert not result.pilot_lng or round(result.pilot_lng, 4) == round(expected_lng, 4)
        assert "must be between" in caplog.text
        assert "to None" in caplog.text

    def test_malformed_packet(self, caplog):
        # Arrange
        oui = "60:60:1F"
        v_spec = b'\x58\x62\x13'
        p_type = b'\x10\x02'
        seq_nr = b'\x4d\x06'
        state_inf = b'\x33\x1f'
        vendor_spec_data = b''.join([v_spec, p_type, seq_nr, state_inf])

        # Act
        result = DjiParser.parse_version_2(b'\x60\x60\x1f' + vendor_spec_data, oui)

        # Assert
        assert not result
        assert "Unable to unpack DJI version 2." in caplog.text

