import datetime
import logging
from typing import Optional

from pydantic import BaseModel, field_validator

__all__ = ["Position", "DroneDto", "HistoryDto"]


class Position(BaseModel):
    """
    Class representing a geographic position. The class also check for valid values. Latitude must be between -90
    and 90, and Longitude must be between -180 and 180.

    Attributes:
        default (bool): If default values for lat and long should be used, if they do not pass the value check.
        lat (float): Latitude of object.
        lng (float): Longitude of object.
    """

    default: bool = False
    lat: float = None
    lng: float = None

    model_config = {
        'validate_assignment': True
    }
    @field_validator("lat")
    def check_lat(cls, v, info):
        if v > 90 or v < -90:
            if info.data.get("default", False):
                logging.warning(f"Latitude must be between -90 and 90. Was {v}. Setting latitude to None.")
                return None
            else:
                raise ValueError(f"Latitude must be between -90 and 90. Was {v}")
        else:
            return v

    @field_validator("lng")
    def check_lng(cls, v, info):
        if v > 180 or v < -180:
            if info.data.get("default", False):
                logging.warning(f"Longitude must be between -180 and 180. Was {v}. Setting longitude to None.")
                return None
            else:
                raise ValueError(f"Longitude must be between -180 and 180. Was {v}")
        else:
            return v


class DroneDto(BaseModel):
    """
    Represents a drone.

    Attributes:
        serial_number (str): Serial number of the drone.
        position (Position): Position of the drone.
        pilot_position (Position, optional): Position of the pilot.
        home_position (Position, optional): Position of the home base.
        rotation (float, optional): rotation of drone (yaw).
        altitude (int, optional): altitude of drone.
        height (int, optional): flight height of drone.
        x_speed (float, optional): drone speed in x direction.
        y_speed (float, optional): drone speed in y direction.
        z_speed (float, optional): drone speed in z direction.
    """
    serial_number: str
    position: Position
    pilot_position: Optional[Position] = None
    home_position: Optional[Position] = None
    rotation: Optional[float] = None
    altitude: Optional[int] = None
    height: Optional[int] = None
    x_speed: Optional[float] = None
    y_speed: Optional[float] = None
    z_speed: Optional[float] = None
    spoofed: Optional[bool] = None


class HistoryDto(BaseModel):
    """
    Represents a location at a specific time in the flight path of a drone.

    Attributes:
        timestamp: (datetime): Timestamp when the location have been captured.
        pos (Position, Optional): Drone position at that point in time.
        pilot_pos (Position, Optional): Pilot position at that point in time.
        home_pos (Position, Optional): Home position at that point in time.
    """
    timestamp: datetime.datetime
    pos: Optional[Position]
    pilot_pos: Optional[Position]
    home_pos: Optional[Position]
