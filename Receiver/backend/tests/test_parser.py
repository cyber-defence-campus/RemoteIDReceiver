from test_parser_ads_stan import TestAdsStanParser
from test_parser_dji import TestDjiV2Parser
from parse.parser_service import parser

wifi_header = b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Dummy header for testing
wifi_header_dij = b'\x60\x60\x1f'  # Dummy header for testing

class TestParser:
  
  def test_ads_stan_parser(self):
    test_parser = TestAdsStanParser()
    packet = test_parser._setup_packet_type_0(uas_id="test-id", uas_id_type=0x32)

    parsed_message = parser.from_wifi(wifi_header + packet, 'FA:0B:BC')
    
    print("MEssage", parsed_message) 
    assert parsed_message is not None
    assert parsed_message.provider == "ADS-STAN"
    assert parsed_message.message is not None
    assert parsed_message.message.message_type == 0x0
    assert parsed_message.is_ads_stan
    assert not parsed_message.is_dji 

  def test_dji_parser(self):
    test_parser = TestDjiV2Parser()
    packet = test_parser.setup_packet()

    parsed_message = parser.from_wifi( wifi_header_dij + packet, '60:60:1F')
    assert parsed_message is not None
    assert parsed_message.provider == "DJI"
    assert parsed_message.message is not None
    assert not parsed_message.is_ads_stan
    assert parsed_message.is_dji