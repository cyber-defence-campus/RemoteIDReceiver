from dataclasses import dataclass
from .direct_remote_id import DirectRemoteIdMessage


@dataclass
class MessagePack(DirectRemoteIdMessage):
  message_type = 0xF
  version = 0x0
  
  messages: list[DirectRemoteIdMessage]
