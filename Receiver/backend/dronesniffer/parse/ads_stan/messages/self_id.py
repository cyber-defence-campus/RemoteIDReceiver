from dataclasses import dataclass, field
from .direct_remote_id import DirectRemoteIdMessage
@dataclass
class SelfIdMessage(DirectRemoteIdMessage):
  message_type: int = field(init=False, default=0x3)
  version: int = field(init=False, default=0x0)
  
  # Description type
  ## 0: Text description
  ## 1-200: Reserved
  ## 201-255: Abaiable for private use
  description_type: int

  # Description
  description: str
