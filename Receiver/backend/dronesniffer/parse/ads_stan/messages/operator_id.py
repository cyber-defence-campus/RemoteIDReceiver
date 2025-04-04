from dataclasses import dataclass, field
from .direct_remote_id import DirectRemoteIdMessage
from models import RemoteId

@dataclass
class OperatorIdMessage(DirectRemoteIdMessage):

  message_type: int = field(init=False, default=0x5)
  version: int = field(init=False, default=0x0)
  
  # Operator ID type
  ## 0: Operator ID
  ## 1-200: Reserved
  ## 201-255: Abaiable for private use
  operator_id_type: int

  # Operator ID
  operator_id: str

  def to_generic(self):
    return RemoteId(
      pilot_registration_number=self.operator_id,
    )   
