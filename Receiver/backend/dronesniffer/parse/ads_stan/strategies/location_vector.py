from .base import ParsingStrategy
from ..messages.location_vector import LocationVectorMessage
import struct
from datetime import datetime, timedelta, timezone
from typing import Optional

TIMESTAMP_UNKNOWN = 0xFFFF


def decode_timestamp(tenths: int, now: Optional[datetime] = None) -> Optional[datetime]:
    """
    The Location message carries tenths of a second since the start of the current UTC hour
    (ASTM F3411). 0xFFFF means unknown. The hour is taken from the receiver clock: the one
    within 30 minutes of now, so a message from the end of the previous hour, or from a
    transmitter whose clock is a little ahead, gets the right hour and date.
    """
    if tenths == TIMESTAMP_UNKNOWN or tenths >= 36000:
        return None
    now = now or datetime.now(timezone.utc)
    timestamp = now.replace(minute=0, second=0, microsecond=0) + timedelta(milliseconds=tenths * 100)
    if timestamp - now > timedelta(minutes=30):
        timestamp -= timedelta(hours=1)
    elif now - timestamp > timedelta(minutes=30):
        timestamp += timedelta(hours=1)
    return timestamp


class LocationVectorParsingStrategy(ParsingStrategy):
    def parse(self, payload: bytes) -> LocationVectorMessage:
        status_byte, track_direction, speed, vertical_speed, latitude, longitude, barometric_pressure, geodetic_altitude, height, hv_acc, baro_speed_acc, timestamp, reserved, _ = struct.unpack('BBBbiiHHHBBHBB', payload) 

        status = status_byte >> 4 # status is bits 4-7
        is_reserved = (status_byte >> 3) & 0b0001 # reserved is bit 3
        height_type = (status_byte >> 2) & 0b0001 # height_type is bit 2
        direction_sentiment = (status_byte >> 1) & 0b0001 # direction sentiment is bit 1
        speed_multiplier = status_byte & 0b0001 # speed multiplier is bit 0

        track_direction = track_direction + 180 if direction_sentiment else track_direction

        if not speed_multiplier:
            speed *= 0.25
        else:
            speed *= 0.75
            speed += 255 * 0.25
            
        vertical_speed *= 0.5
        latitude /=  10 ** 7
        longitude /= 10 ** 7
        
        barometric_pressure = (barometric_pressure * 0.5) - 1000
        geodetic_altitude = (geodetic_altitude * 0.5) - 1000
        height = (height * 0.5) - 1000
        
        v_acc = (hv_acc >> 4) & 0b00001111 # bits 7..4
        h_acc = hv_acc & 0b00001111 # bits 3..0
        baro_acc = (baro_speed_acc >> 4) & 0b00001111 # bits 7..4
        speed_acc = baro_speed_acc & 0b00001111 # bits 3..0
        timestamp_acc = reserved & 0b00001111 # bits 3..0

        timestamp = decode_timestamp(timestamp)
        
        return LocationVectorMessage(status, is_reserved, height_type, track_direction, speed, vertical_speed, latitude, longitude, barometric_pressure, geodetic_altitude, height, timestamp, h_acc, v_acc, speed_acc,baro_acc, timestamp_acc)