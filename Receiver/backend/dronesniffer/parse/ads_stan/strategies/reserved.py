from .base import ParsingStrategy
from ..messages.direct_remote_id import DirectRemoteIdMessage

class ReservedParsingStrategy(ParsingStrategy):
    def parse(self, payload: bytes) -> DirectRemoteIdMessage:
        message = DirectRemoteIdMessage()
        message.message_type = 0x2
        message.version = 0x0
        message.note = "Reserved for future use"
        return message
