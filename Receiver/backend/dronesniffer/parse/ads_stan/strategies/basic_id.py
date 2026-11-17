from .base import ParsingStrategy
from ..messages.basic_id import BasicIdMessage

class BasicIdParsingStrategy(ParsingStrategy):
    def parse(self, payload: bytes) -> BasicIdMessage:
        id_type = payload[0] >> 4  # first four bits
        ua_type = payload[0] & 0x0F  # last four bits
        # UAS ID: 20 bytes, then 3 reserved bytes that are not part of the ID
        id_number = payload[1:21].decode().rstrip('\x00').strip()
        return BasicIdMessage(id_type, ua_type, id_number)
