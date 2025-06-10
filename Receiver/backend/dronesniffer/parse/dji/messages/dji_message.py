from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from parse.parser import ParsedMessage

@dataclass
class DjiMessage(ParsedMessage):
    """Message class for DJI Remote ID protocol (both version 1 and 2)"""
    serial_number: str
    lng: float
    lat: float
    height: float
    x_speed: float
    y_speed: float
    yaw: float
    home_lng: float
    home_lat: float
    uuid: str
    timestamp: datetime
    oui: str

    # Version 2
    pilot_lat: Optional[float] = None
    pilot_lng: Optional[float] = None

    def __post_init__(self):
        super().__init__(provider="DJI")    
