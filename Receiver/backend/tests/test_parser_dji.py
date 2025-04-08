import math
import struct

import pytest

from parse.dji.parser import DjiParser

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
    (-91, -20, -91, -20),
    (91, -20, 91, -20),
    (22, -181, 22, -181),
    (22, 181, 22, 181),
]

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

