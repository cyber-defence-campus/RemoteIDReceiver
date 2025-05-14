from .base import ParsingStrategy
from ..messages.self_id import SelfIdMessage

class SelfIdParsingStrategy(ParsingStrategy):
    def parse(self, payload: bytes) -> SelfIdMessage:

        description_type = payload[0]
        description = payload[1:].decode('ascii').rstrip('\x00').strip()

        return SelfIdMessage(description_type, description)