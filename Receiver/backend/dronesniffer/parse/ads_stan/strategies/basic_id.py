from .base import ParsingStrategy
from ..messages.basic_id import BasicIdMessage

class BasicIdParsingStrategy(ParsingStrategy):
    def parse(self, payload: bytes) -> BasicIdMessage:
        id_type = payload[0] >> 4  # first four bits
        ua_type = payload[0] & 0x0F  # last four bits
        id_number = payload[1:].decode().rstrip('\x00').strip()
        return BasicIdMessage(id_type, ua_type, id_number)
