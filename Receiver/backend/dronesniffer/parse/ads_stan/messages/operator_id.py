from dataclasses import dataclass, field
from .direct_remote_id import DirectRemoteIdMessage

@dataclass
class OperatorIdMessage(DirectRemoteIdMessage):
  
  # Operator ID type
  ## 0: Operator ID
  ## 1-200: Reserved
  ## 201-255: Abaiable for private use
  operator_id_type: int

  # Operator ID
  operator_id: str
  
  def __post_init__(self):
    """Initialize the parent class after dataclass initialization."""
    super().__init__(message_type=0x5, version=0x0)
