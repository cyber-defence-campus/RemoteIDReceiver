import logging

import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11EltVendorSpecific

from drone_sniffer import filter_frames
from parse.handler import DjiHandler, AsdStanHandler, DefaultHandler
from parse.dji.parser import DjiParser
from parse.ads_stan.parser import DirectRemoteIdMessageParser

PARROT_OUI = PARROT_OUI = ["90:3a:e6", "00:12:1C", "90:03:B7", "A0:14:3D", "00:26:7E"]

class TestIsADrone:
    @pytest.mark.parametrize("oui", [*DjiParser.oui, DirectRemoteIdMessageParser.oui])
    def test_when_drone_oui_then_true(self, oui):
        handler = DjiHandler(AsdStanHandler(DefaultHandler(None)))
        result = handler.is_drone(oui)

        assert result

    @pytest.mark.parametrize("oui", ["", " ", "0", "12:12:12", *PARROT_OUI])
    def test_when_not_drone_oui_then_false(self, oui):
        handler = DjiHandler(AsdStanHandler(DefaultHandler(None)))
        result = handler.is_drone(oui)

        assert not result


@pytest.fixture()
def test_beacon_frame():
    # 802.11 frame
    source_addr = "60:60:1f:c6:0e:cc"
    dest_addr = "ff:ff:ff:ff:ff:ff"
    dot11 = Dot11(type=0, subtype=8, addr1=source_addr, addr2=dest_addr)
    # SSID
    ssid = "Test_SSID"
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    # Beacon layer
    drone_info = b'&7\x12Xb\x13\x10\x02M\x063\x1fK6RE0WENAH9P8QAL\x01\x9f"\x00<\xf5\x1f\x007\x00d\x004\x08<\x0f\x84\x03\xbc\xd0?<\xa0[\x00\x00\x00\x00\x18#\x95\x00\x17\x84r\x00\x17\x84r\x00\x18#\x95\x00X\x06\x00alessa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    vendor = Dot11EltVendorSpecific(len=len(drone_info), oui=2504466, info=drone_info)
    # Beacon layer
    beacon = Dot11Beacon()
    # stack all the layers and add a RadioTap
    return RadioTap() / dot11 / beacon / essid / vendor


class TestFilterFrames:
    @pytest.mark.skip("Test is not yet ready")
    def test_when_real_drone_frame_then_log(self, caplog, test_beacon_frame):
        caplog.set_level(logging.INFO)

        filter_frames(test_beacon_frame)

        assert "spoofer oui" in caplog.text
