from dataclasses import dataclass, field
from .direct_remote_id import DirectRemoteIdMessage
@dataclass
class LocationVectorMessage(DirectRemoteIdMessage):
  
  message_type: int = field(init=False, default=0x1)
  version: int = field(init=False, default=0x0)

  # Operational status
  ## 0: Undeclared
  ## 1: Ground
  ## 2: Airborne
  ## 3: Emergency
  ## 4–15: Reserved
  operational_status: int

  is_reserved: bool 
  
  # 0: Above take-off, 1: AGL, 2,3: Reserved
  height_type: int

  # Direction expressed as the route course measured clockwise from true north. -180 to 180
  track_direction: int

  # Speed in m/s
  speed: int

  # Vertical speed in m/s
  vertical_speed: int
  
  # Latitude in degrees
  latitude: float

  # Longitude in degrees
  longitude: float
  
  altitude_barometric: int # −1 000–31 767m
  altitude_geodetic: int # −1 000–31 767m
  height_above_takeoff: int # -1000–31 767m
  
  timestamp: int

  # Horizontal accuracy
  ## 0: ≥ 18,52 km (10 NM) or unknown
  ## 1: < 18,52 km (10 NM)
  ## 2: < 7,408 km (4 NM)
  ## 3: < 3,704 km (2 NM)
  ## 4: < 1,852 m (1 NM)
  ## 5: < 926 m (0,5 NM)
  ## 6: < 555,6 m (0,3 NM)
  ## 7: < 185,2 m (0,1 NM)
  ## 8: < 92,6 m (0,05 NM)
  ## 9: < 30 m
  ## 10: < 10 m
  ## 11: < 3 m
  ## 12: < 1 m
  ## 13–15: Reserved
  accuracy_horizontal: int 

  # Vertical accuracy
  ## 0: ≥ 150 m or unknown
  ## 1: < 150 m
  ## 2: < 45 m
  ## 3: < 25 m
  ## 4: < 10 m
  ## 5: < 3 m
  ## 6: < 1 m
  ## 7–15: Reserved
  accuracy_vertical: int 
  
  accuracy_speed: int
  accuracy_barometric_altitude: int
  accuracy_timestamp: int
