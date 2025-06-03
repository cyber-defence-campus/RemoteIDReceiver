from abc import ABC, abstractmethod
from ..messages.direct_remote_id import DirectRemoteIdMessage

class ParsingStrategy(ABC):
    @abstractmethod
    def parse(self, payload: bytes) -> DirectRemoteIdMessage:
        pass 