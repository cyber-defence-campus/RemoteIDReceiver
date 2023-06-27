import struct

import pytest
from scapy.layers.dot11 import Dot11Elt, Dot11EltVendorSpecific, Dot11, RadioTap, Dot11Beacon


@pytest.fixture()
def test_beacon_frame_asd_stan():
    dest_addr = 'ff:ff:ff:ff:ff:ff'  # address 1
    src_addr = '90:3a:e6:5b:c8:a8'  # address 2
    header = b'\x0d\x5d\xf0\x19\x04'  # oui: fa:0b:bc (ASD-STAN)
    msg_type_5 = b'\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    # IE: SSID
    drone_ssid = 'AnafiThermal-Spoofed'
    ie_ssid = Dot11Elt(ID='SSID', len=len(drone_ssid), info=drone_ssid)
    serial_byte = struct.pack("<20s", "test_serial_number12")
    msg_type_0 = b''.join([b'\x00\x12', serial_byte, b'\x00\x00\x00'])

    ew_dir_byte = struct.pack("<B", 32)  # a standard value to set E/W direction segment bit
    direction_byte = struct.pack("<B", 90)  # rotation of drone in degrees
    lat_byte = struct.pack("<i", 473763399)  # drone lat, lat of Kasernenareal in Zurich
    lng_byte = struct.pack("<i", 85312562)  # drone lng, lng of Kasernenareal in Zurich
    tenth_seconds_byte = struct.pack("<H", 5060)  # tenth of seconds since hour
    msg_type_1 = b''.join(
        [b'\x10', ew_dir_byte, direction_byte, b'\x00\x00', lat_byte, lng_byte, b'\x00\x00\x00\x00\xd0\x07\x00\x00',
         tenth_seconds_byte, b'\x00\x00'])

    pilot_lat_byte = struct.pack("<i", 473764499)  # pilot lat, close to drone lat
    pilot_lng_byte = struct.pack("<i", 85317762)  # pilot lng, close to drone lng
    msg_type_4 = b''.join([b'\x40\x05', pilot_lat_byte, pilot_lng_byte,
                           b'\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00'])

    vendor_spec_data = b''.join([header, msg_type_0, msg_type_1, msg_type_4, msg_type_5])
    ie_vendor_parrot = Dot11EltVendorSpecific(ID=221, len=len(vendor_spec_data), oui=16387004,
                                                    info=vendor_spec_data)

    return RadioTap() / Dot11(type=0, subtype=8, addr1=dest_addr, addr2=src_addr, addr3=src_addr) / Dot11Beacon() / \
        ie_ssid / ie_vendor_parrot


@pytest.fixture()
def asd_stan_packet():
    serial_byte = struct.pack("<20s", "test_serial_number12".encode())
    msg_type_0 = b''.join([b'\x00\x12', serial_byte, b'\x00\x00\x00'])

    ew_dir_byte = struct.pack("<B", 32)  # a standard value to set E/W direction segment bit
    direction_byte = struct.pack("<B", 90)  # rotation of drone in degrees
    lat_byte = struct.pack("<i", 473763399)  # drone lat, lat of Kasernenareal in Zurich
    lng_byte = struct.pack("<i", 85312562)  # drone lng, lng of Kasernenareal in Zurich
    tenth_seconds_byte = struct.pack("<H", 5060)  # tenth of seconds since hour
    msg_type_1 = b''.join(
        [b'\x10', ew_dir_byte, direction_byte, b'\x00\x00', lat_byte, lng_byte, b'\x00\x00\x00\x00\xd0\x07\x00\x00',
         tenth_seconds_byte, b'\x00\x00'])

    pilot_lat_byte = struct.pack("<i", 473764499)  # pilot lat, close to drone lat
    pilot_lng_byte = struct.pack("<i", 85312262)  # pilot lng, close to drone lng
    msg_type_4 = b''.join([b'\x40\x05', pilot_lat_byte, pilot_lng_byte,
                           b'\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00'])
    header = b'\x0d\x5d\xf0\x19\x04'  # oui: fa:0b:bc (ASD-STAN)
    msg_type_5 = b'\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    vendor_spec_data = b''.join([header, msg_type_0, msg_type_1, msg_type_4, msg_type_5])
    return Dot11EltVendorSpecific(ID=221, len=len(vendor_spec_data), oui=16387004, info=vendor_spec_data)
