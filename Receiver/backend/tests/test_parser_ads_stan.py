import struct 
import pytest
from parse.ads_stan.parser import DirectRemoteIdMessageParser

class TestAdsStanParser:
  
  def _setup_packet_type_0(self, uas_id="test-id", uas_id_type=0x32): 
    header = struct.pack('B', 0x01) # type 0 version 1
    id_ua_type = struct.pack('B', uas_id_type) # ID Type, UA Type

    uas_id = uas_id.encode('ascii').ljust(20, b'\x00')  # pad

    pad = b'\x00\x00\x00' # reserved bytes

    return header + id_ua_type + uas_id + pad

  def _setup_packet_type_1(self):
    header = struct.pack('B', 0x11) # type 1 version 1
     
    status_flags = '00100110' # status: airborne, height_type: AGL, direction_sentiment: 1, speed_multiplier: 0
    status_flags = int(status_flags, 2).to_bytes(1, 'little')

    track_direction = 10 # 0-359 degrees
    track_direction = struct.pack('B', track_direction) # 10 with direction sentiment 1 should parse to 190 deg. according to the standard (+180)
    
    speed = 20 # should parse to 5 m/s
    speed = struct.pack('B', speed)
    
    vertical_speed = 15 # should parse to 7.5 m/s
    vertical_speed = struct.pack('b', vertical_speed)

    lat = 472000000 # drone lat, lat of Kasernenareal in Zurich
    lng = 85400000
     
    lat_byte = struct.pack("<i", lat)  # drone lat, lat of Kasernenareal in Zurich
    lng_byte = struct.pack("<i", lng)  # drone lng, lng of Kasernenareal in Zurich

    pressure_altitude = 2021 # should parse to 10.5 m
    pressure_altitude = struct.pack("<H", pressure_altitude)
    
    gnss_altitude = 2021 # should parse to 10.5 m
    gnss_altitude = struct.pack("<H", gnss_altitude)
    
    height = 2021 # should parse to 10.5 m
    height = struct.pack("<H", height)
    
    accuracy_flags = '01000010'
    accuracy_flags = int(accuracy_flags, 2).to_bytes(1, 'little')
    
    baro_accuracy_flags = '10000100'
    baro_accuracy_flags = int(baro_accuracy_flags, 2).to_bytes(1, 'little')
    
    timestamp = 3611 # should parse to 6 mins, 1.1s
    timestamp = struct.pack("<H", timestamp)
    
    timestamp_accuracy = '00000100'
    timestamp_accuracy = int(timestamp_accuracy, 2).to_bytes(1, 'little')
    
    reserved = b'\x00'

    return b''.join([header, status_flags, track_direction, speed, vertical_speed, lat_byte, lng_byte, pressure_altitude, gnss_altitude, height, accuracy_flags, baro_accuracy_flags, timestamp, timestamp_accuracy, reserved])
     

  def _setup_packet_type_3(self, description="test-id-3", description_type=201):
    header = struct.pack('B', 0x31)
    description_type = struct.pack('B', description_type)
    description = description.encode('ascii').ljust(23, b'\x00')  # pad
    return header + description_type + description
     
   
  def _setup_packet_type_4(self):
    header = struct.pack('B', 0x41)
    
    flags = '00000110' # classification: EU, pilot_location: Fixed
    flags = int(flags, 2).to_bytes(1, 'little')
    
    lat = 472000000 
    lng = 85400000
    
    lat = struct.pack("<i", lat)  # drone lat, lat of Kasernenareal in Zurich
    lng = struct.pack("<i", lng)  # drone lng, lng of Kasernenareal in Zurich
    
    area_count = struct.pack('H', 6) 
    area_radius = struct.pack('B', 2)
    area_ceil = struct.pack('H', 2021) # 10.5 m
    area_floor = struct.pack('H', 2021) # 10.5 m

    ua_cat = '00110101' # UA Category: 3, Class: 5
    ua_cat = int(ua_cat, 2).to_bytes(1, 'little')

    pilot_alt = struct.pack('H', 2021) # 10.5 m
   
    pad = b'\x00\x00\x00\x00\x00' # reserved bytes

    return b''.join([header, flags, lat, lng, area_count, area_radius, area_ceil, area_floor, ua_cat, pilot_alt, pad])
     
  def _setup_packet_type_5(self, operator_id="operator-id", operator_id_type=242):
    header = struct.pack('B', 0x51)
    
    operator_id_type = struct.pack('B', operator_id_type)
    operator_id = operator_id.encode('ascii').ljust(20, b'\x00')  # pad 
    
    pad = b'\x00\x00\x00' # reserved bytes
    
    return header + operator_id_type + operator_id + pad 
    
  def _setup_packet_type_f(self, messages):
    header = struct.pack('B', 0xF1)
    
    message_length = b'\x13' # hardcoded per protocol
    n_messages = struct.pack('B', len(messages))

    return header + message_length + n_messages + b''.join(messages)
    
    
  
  
  def test_message_type_0(self):
    id_type = 0x32
    test_id = "test-id"
    packet = self._setup_packet_type_0(test_id, id_type)

    assert len(packet) == 25 # 1 byte header, 1 byte id_type, 20 byte id, 3 byte pad
    
    parsed = DirectRemoteIdMessageParser.parse(packet)
    print(parsed) 
    assert parsed.message_type == 0x0
    assert parsed.version == 0x0
    assert parsed.id_type == 3 
    assert parsed.ua_type == 2 
    assert parsed.uas_id == test_id 

    
  def test_message_type_1(self):
    packet = self._setup_packet_type_1()

    assert len(packet) == 25
    
    parsed = DirectRemoteIdMessageParser.parse(packet)
    
    assert parsed.message_type == 0x1
    assert parsed.version == 0x0

    assert parsed.operational_status == 2  # Airborne from status_flags
    assert parsed.height_type == 1  # AGL from status_flags
    assert parsed.track_direction == 190  # From track_direction bytes
    assert parsed.latitude == pytest.approx(47.2)  # From lat_byte
    assert parsed.longitude == pytest.approx(8.54)  # From lng_byte
    assert parsed.altitude_barometric == pytest.approx(10.5)  # From pressure_altitude
    assert parsed.altitude_geodetic == pytest.approx(10.5)  # From gnss_altitude  
    assert parsed.height_above_takeoff == pytest.approx(10.5)  # From height
    assert parsed.speed == pytest.approx(5)  # From speed
    assert parsed.vertical_speed == pytest.approx(7.5)  # From vertical_speed
    assert parsed.timestamp.minute== 6  # From timestamp bytes
    assert parsed.timestamp.second == 1  # From timestamp bytes
    assert parsed.accuracy_horizontal == 2  # From accuracy_flags
    assert parsed.accuracy_vertical == 4  # From accuracy_flags
    assert parsed.accuracy_speed == 4  # From baro_accuracy_flags
    assert parsed.accuracy_barometric_altitude == 8  # From baro_accuracy_flags

    
    
  def test_message_type_3(self):
    description = "test-id-3"
    description_type = 201
    packet = self._setup_packet_type_3(description, description_type)

    assert len(packet) == 25
    
    parsed = DirectRemoteIdMessageParser.parse(packet)
    
    assert parsed.message_type == 0x3
    assert parsed.version == 0x0
    assert parsed.description_type == description_type
    assert parsed.description == description  

  def test_type_4(self):
    packet = self._setup_packet_type_4()

    assert len(packet) == 25
    
    parsed = DirectRemoteIdMessageParser.parse(packet)
    
    assert parsed.message_type == 0x4
    assert parsed.version == 0x0
    assert parsed.classification_type == 1  # EU
    assert parsed.location_source == 2 # fixed
    assert parsed.pilot_latitude == pytest.approx(47.2)
    assert parsed.pilot_longitude == pytest.approx(8.54)
    assert parsed.area_count == 6
    assert parsed.area_radius == pytest.approx(0.2)
    assert parsed.area_ceiling == pytest.approx(10.5)
    assert parsed.area_floor == pytest.approx(10.5)
    assert parsed.ua_category == 3  
    assert parsed.ua_class == 5  
    assert parsed.pilot_geodetic_altitude == pytest.approx(10.5)

  def test_type_5(self):
    operator_id = "operator-id"
    operator_id_type = 204
    packet = self._setup_packet_type_5(operator_id, operator_id_type)

    assert len(packet) == 25
    
    parsed = DirectRemoteIdMessageParser.parse(packet)
    
    assert parsed.message_type == 0x5
    assert parsed.version == 0x0
    assert parsed.operator_id_type == operator_id_type
    assert parsed.operator_id == operator_id
  
  def test_type_f(self):
    message_1 = self._setup_packet_type_0("test-id-1", 0x32)
    message_2 = self._setup_packet_type_1()
    message_4 = self._setup_packet_type_3("test-id-4", 201)
    message_5 = self._setup_packet_type_4()
     
    messages = [message_1, message_2,  message_4, message_5]
    
    packet = self._setup_packet_type_f(messages)
    
    parsed = DirectRemoteIdMessageParser.parse(packet)
    
    assert parsed.message_type == 0xF
    assert parsed.version == 0x0
    assert len(parsed.messages) == 4
