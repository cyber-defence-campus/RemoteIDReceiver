from dataclasses import dataclass, field
from .direct_remote_id import DirectRemoteIdMessage

@dataclass
class SystemMessage(DirectRemoteIdMessage):
  message_type: int = field(init=False, default=0x4)
  version: int = field(init=False, default=0x0)

  # Classification Type
  ## 0 = Undeclared
  ## 1 = EU
  ## 2–7 = Reserved
  classification_type: int
  
  # Location Source
  ## 0 = Take-Off Location
  ## 1 = Live GNSS
  ## 2 = Fixed Location
  location_source: int
  
  pilot_latitude: float
  pilot_longitude: float
  
  area_count: int
  area_radius: int
  area_ceiling: int
  area_floor: int

  # UA Category
  ## 0: Undefined
  ## 1: Open
  ## 2: Specific
  ## 3: Certified
  ## 4–15: Reserved
  ua_category: int

  # UA Class
  ## 0: Undefined
  ## 1: Class 0
  ## 2: Class 1
  ## 3: Class 2
  ## 4: Class 3
  ## 5: Class 4
  ## 6: Class 5
  ## 7: Class 6
  ## 8–15: Reserved
  ua_class: int

  pilot_geodetic_altitude: int
