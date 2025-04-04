from dataclasses import dataclass
from .direct_remote_id import DirectRemoteIdMessage
from models import RemoteId


@dataclass
class MessagePack(DirectRemoteIdMessage):
  message_type = 0xF
  version = 0x0
  
  messages: list[DirectRemoteIdMessage]

  def to_generic(self):
    merged = RemoteId()
    
    parsed_messages = [msg.to_generic() for msg in self.messages] 
    for msg in parsed_messages:
      for field in msg.model_fields:
        value = getattr(msg, field)
        if value is not None:
          setattr(merged, field, value)
                    
    return merged
    
