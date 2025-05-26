from dataclasses import dataclass, field
from .direct_remote_id import DirectRemoteIdMessage
@dataclass
class SelfIdMessage(DirectRemoteIdMessage):
  
  # Description type
  ## 0: Text description
  ## 1-200: Reserved
  ## 201-255: Abaiable for private use
  description_type: int

  # Description
  description: str
  
  def __post_init__(self):
    """Initialize the parent class after dataclass initialization."""
    super().__init__(message_type=0x3, version=0x0)
