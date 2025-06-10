from .base import ParsingStrategy
from ..messages.operator_id import OperatorIdMessage
class OperatorIdParsingStrategy(ParsingStrategy):
    def parse(self, payload: bytes) -> OperatorIdMessage:
        id_type = payload[0]
        id_number = payload[1:].decode('ascii').rstrip('\x00').strip()
        return OperatorIdMessage(id_type, id_number)
