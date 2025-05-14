from abc import ABC, abstractmethod

class DirectRemoteIdMessage(ABC):
    """
    A class that represents a Direct Remote ID message.
    Attributes:
        message_type: The type of the message (0x0-0x5, 0xF).
        version: The version of the message (0x0-0xF).
    """
    message_type: int
    version: int
