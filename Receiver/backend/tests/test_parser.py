from test_parser_ads_stan import TestAdsStanParser
from test_parser_dji import TestDjiV2Parser
from parse.parser_service import parser

wifi_header = b'\xfa\x0b\xbc\x0d\x00\xf0\x19\x01'  # OUI, vendor type 0x0D, counter, pack header
wifi_header_dij = b'\x60\x60\x1f'  # Dummy header for testing

# Vendor specific element bodies as process_packet passes them (OUI, vendor type, counter, payload).
# Beacon from the Open Drone ID sample captures (https://github.com/opendroneid/wireshark-dissector,
# Apache-2.0). The reserved bytes after its UAS ID are not zero.
odid_beacon = bytes.fromhex(
  "fa0bbc0dd0f0190500004d464731413031323334353637383900000000000050f610005c527ebcba251ba88cb4b6"
  "0000aa099808394100000a00300052656372656174696f6e616c00000000000000000000004004a485251b6edbb3"
  "b601003200000000150000000000000050004742522d4f502d31323341424344000000000000000000"
)
# Wi-Fi Direct element (vendor type 0x09) from resources/wifi/parrot_anafi4_spoofed.pcapng
wifi_direct = bytes.fromhex("506f9a090202000001030600da9c67351f56")
# NAN element (vendor type 0x13) from a NAN cluster beacon in the Open Drone ID sample captures
nan_beacon = bytes.fromhex("506f9a13000200feea010d0084cca8604324eafe00000000000206008869199d9209")

class TestParser:
  
  def test_ads_stan_parser(self):
    test_parser = TestAdsStanParser()
    packet = test_parser._setup_packet_type_0(uas_id="test-id", uas_id_type=0x32)

    parsed_message = parser.from_wifi(wifi_header + packet, 'FA:0B:BC')
    
    print("MEssage", parsed_message) 
    assert parsed_message is not None
    assert parsed_message.provider == "ADS-STAN"
    assert parsed_message.message_type == 0x0

  def test_dji_parser(self):
    test_parser = TestDjiV2Parser()
    packet = test_parser.setup_packet()

    parsed_message = parser.from_wifi( wifi_header_dij + packet, '60:60:1F')
    assert parsed_message is not None
    assert parsed_message.provider == "DJI"

  def test_ads_stan_beacon_with_reserved_bytes(self):
    parsed_message = parser.from_wifi(odid_beacon, 'FA:0B:BC')

    assert parsed_message is not None
    basic_id, location = parsed_message.messages[0], parsed_message.messages[1]
    assert basic_id.uas_id == "MFG1A0123456789"
    assert location.latitude == 45.5457468
    assert location.longitude == -122.9681496

  def test_wifi_alliance_elements_are_not_remote_id(self):
    assert parser.from_wifi(wifi_direct, '50:6F:9A') is None
    assert parser.from_wifi(nan_beacon, '50:6F:9A') is None
