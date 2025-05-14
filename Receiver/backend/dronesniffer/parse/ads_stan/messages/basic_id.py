from dataclasses import dataclass, field
from .direct_remote_id import DirectRemoteIdMessage

@dataclass
class BasicIdMessage(DirectRemoteIdMessage):
  
  message_type: int = field(init=False, default=0x0)
  version: int = field(init=False, default=0x0)
   
  # Identification type
  ## 0: None
  ## 1: Serial Number
  ## 2: CAA assigned registration ID
  id_type: int
  
  # UA type
  ## 0: None or not declared
  ## 1: Aeroplane or fixed wing
  ## 2: Helicopter or multirotor
  ## 3: Gyroplane
  ## 4: Hybrid lift (fixed wing aircraft with vertical take-off and landing capability)
  ## 5: Ornithopter
  ## 6: Glider
  ## 7: Kite
  ## 8: Free balloon
  ## 9: Captive balloon
  ## 10: Airship (such as a blimp)
  ## 11: Free fall/parachute (unpowered)
  ## 12: Rocket
  ## 13: Tethered powered aircraft
  ## 14: Ground obstacle
  ## 15: other
  ua_type: int
  
  # UAS ID
  uas_id: str
  