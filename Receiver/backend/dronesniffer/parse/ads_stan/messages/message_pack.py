from dataclasses import dataclass
from .direct_remote_id import DirectRemoteIdMessage


@dataclass
class MessagePack(DirectRemoteIdMessage):
  messages: list[DirectRemoteIdMessage]
  
  def __post_init__(self):
    """Initialize the parent class after dataclass initialization."""
    super().__init__(message_type=0xF, version=0x0)
