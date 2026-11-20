import pytest
from scapy.layers.dot11 import Dot11, RadioTap
from sqlmodel import SQLModel, create_engine
from sqlalchemy.orm import sessionmaker

pytest.importorskip("remoteid")

import trust
from models.direct_remote_id import BasicIdMessage, LocationMessage, SystemMessage, Base
from services.drone_service_ads import DroneServiceAds

# Beacon (with RadioTap header) from the Open Drone ID sample captures
# (https://github.com/opendroneid/wireshark-dissector, Apache-2.0).
ODID_BEACON = bytes.fromhex(
    "00b511002e18000000028509a000df010480000000ffffffffffff84cca860432484cca8604324000d00000000000000"
    "00b80b2104030106000e4742522d4f502d31323341424344dd85fa0bbc0dd0f0190500004d46473141303132333435"
    "3637383900000000000050f610005c527ebcba251ba88cb4b60000aa099808394100000a00300052656372656174696f"
    "6e616c00000000000000000000004004a485251b6edbb3b601003200000000150000000000000050004742522d4f502d"
    "31323341424344000000000000000000"
)
ODID_SENDER = "84:cc:a8:60:43:24"

# Beacon as sent by https://github.com/jjshoots/RemoteIDSpoofer (ESP8266 sketch), built from its source
# without transmitting.
SPOOFER_BEACON = bytes.fromhex(
    "80000000ffffffffffff0067c66973510067c6697351200040b55e08efef05000a0011000010375532306f304a3930"
    "7841304757584901088b9682840c18306003010605040002000007065a5a20010b1432046c122448dd0918fe340301"
    "00000000dd21fa0bbc0d01f21901320052656372656174696f6e616c0000000000000000000000"
)
SPOOFER_SENDER = "00:67:c6:69:73:51"


def _packet(layer, data, time):
    packet = layer(data)
    packet.time = time
    return packet


@pytest.fixture(autouse=True)
def fresh_tracker():
    trust.reset()
    yield
    trust.reset()


def test_unknown_sender_has_no_verdict():
    assert trust.verdict(ODID_SENDER) is None


def test_reference_transmitter_is_plausible():
    trust.observe(_packet(RadioTap, ODID_BEACON, 1621633931.162))

    verdict = trust.verdict(ODID_SENDER)
    assert verdict is not None
    assert verdict.verdict == "plausible"
    assert verdict.uas_id == "MFG1A0123456789"


def test_spoofer_is_spoofed():
    trust.observe(_packet(Dot11, SPOOFER_BEACON, 1794916800.2))

    verdict = trust.verdict(SPOOFER_SENDER)
    assert verdict.verdict == "spoofed"
    assert "known_spoofer" in verdict.reasons
    assert verdict.spoofer == "jjshoots/RemoteIDSpoofer"


def test_frame_that_is_not_remote_id_is_ignored():
    trust.observe(_packet(Dot11, SPOOFER_BEACON[:40], 1794916800.2))

    assert trust.verdict(SPOOFER_SENDER) is None


def test_drone_state_reports_the_verdict():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    # Operator next to the drone, so the 15 km check alone does not flag it
    session.add(BasicIdMessage(sender_id=SPOOFER_SENDER, uas_id="7U20o0J90xA0GWXI"))
    session.add(LocationMessage(sender_id=SPOOFER_SENDER, latitude=47.0, longitude=8.0))
    session.add(SystemMessage(sender_id=SPOOFER_SENDER, pilot_latitude=47.001, pilot_longitude=8.0))
    session.commit()
    session.close()
    service = DroneServiceAds(engine)

    before = service.get_drone_state(SPOOFER_SENDER)
    assert before.spoofed is False
    assert before.trust is None

    trust.observe(_packet(Dot11, SPOOFER_BEACON, 1794916800.2))
    after = service.get_drone_state(SPOOFER_SENDER)
    assert after.spoofed is True
    assert after.trust == "spoofed"
    assert "known_spoofer" in after.trust_reasons


def test_without_remoteid_checks_are_off(monkeypatch):
    monkeypatch.setattr(trust, "_tracker", None)

    trust.observe(_packet(Dot11, SPOOFER_BEACON, 1794916800.2))
    assert trust.verdict(SPOOFER_SENDER) is None
