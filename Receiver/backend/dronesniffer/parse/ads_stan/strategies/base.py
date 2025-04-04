from abc import ABC, abstractmethod

class ParsingStrategy(ABC):
    @abstractmethod
    def parse(self, payload: bytes) -> dict:
        pass 