from types import SimpleNamespace

from ble import BleRemoteIdSniffer, is_remote_id_service
from parse.ads_stan.parser import DirectRemoteIdMessageParser


def _basic_id_message(uas_id: str = "BLE-TEST") -> bytes:
    return b"\x01\x32" + uas_id.encode("ascii").ljust(20, b"\0") + b"\0\0\0"


def test_ble_service_data_parses_after_application_code_and_counter():
    parsed = DirectRemoteIdMessageParser.from_bluetooth(b"\x0d\x7f" + _basic_id_message())

    assert parsed.message_type == 0
    assert parsed.uas_id == "BLE-TEST"


def test_ble_parser_rejects_other_application_codes():
    assert DirectRemoteIdMessageParser.from_bluetooth(b"\x0c\x00" + _basic_id_message()) is None


def test_remote_id_service_uuid_is_recognized():
    assert is_remote_id_service("0000fffa-0000-1000-8000-00805f9b34fb")
    assert not is_remote_id_service("0000feaa-0000-1000-8000-00805f9b34fb")


def test_scanner_forwards_only_remote_id_service_data():
    received = []
    sniffer = BleRemoteIdSniffer("hci0", lambda address, data: received.append((address, data)))
    device = SimpleNamespace(address="12:34:56:78:9A:BC")

    sniffer._on_detection(
        device,
        SimpleNamespace(service_data={"0000fffa-0000-1000-8000-00805f9b34fb": b"\x0d\x01data"}),
    )
    sniffer._on_detection(
        device,
        SimpleNamespace(service_data={"0000feaa-0000-1000-8000-00805f9b34fb": b"\x0d\x01data"}),
    )

    assert received == [("12:34:56:78:9A:BC", b"\x0d\x01data")]
