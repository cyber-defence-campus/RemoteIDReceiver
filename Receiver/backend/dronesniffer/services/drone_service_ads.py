from sqlalchemy.orm import Session
from typing import List, Dict, Any
from datetime import datetime, timedelta
from .drone_service import DroneService

from models.direct_remote_id import (
    BasicIdMessage, 
    LocationMessage, 
    SystemMessage, 
)
from models.dtomodels import DroneDto, Position
import logging

class DroneServiceAds(DroneService):
    """Service for handling drone-related operations"""
    
    def __init__(self, db_enginge):
        self.db_engine = db_enginge
        
    def get_all_drone_senders(self) -> List[str]:
        # BasicID must be sent at least once every 3 seconds. Hence it is a good indicator of the drone's presence.
        with Session(self.db_engine) as session:
            # Use distinct to get unique sender IDs
            ids = session.query(BasicIdMessage.sender_id).distinct().all()
            # Extract sender IDs from the result
            return [id[0] for id in ids]

    def get_active_drone_senders(self) -> List[str]:
        # BasicID must be sent at least once every 3 seconds. Hence it is a good indicator of the drone's presence.
        time_threshold = datetime.now() - self._active_drone_max_age
        with Session(self.db_engine) as session:
            # Use distinct to get unique sender IDs
            ids = session.query(BasicIdMessage.sender_id).filter(BasicIdMessage.received_at > time_threshold).distinct().all()
            # Extract sender IDs from the result
            return [id[0] for id in ids]

    def get_drone_state(self, sender_id: str) -> DroneDto:
        with Session(self.db_engine) as session:
            basic_id = session.query(BasicIdMessage).filter(BasicIdMessage.sender_id == sender_id).order_by(BasicIdMessage.received_at.desc()).first()
            location = session.query(LocationMessage).filter(LocationMessage.sender_id == sender_id).order_by(LocationMessage.received_at.desc()).first()
            system = session.query(SystemMessage).filter(SystemMessage.sender_id == sender_id).order_by(SystemMessage.received_at.desc()).first()
            first_location = session.query(LocationMessage).filter(LocationMessage.sender_id == sender_id).order_by(LocationMessage.received_at.asc()).first()

        return DroneDto(
            serial_number=basic_id.sender_id,
            position=Position(lat=location.latitude, lng=location.longitude) if location else None,
            pilot_position=Position(lat=system.pilot_latitude, lng=system.pilot_longitude) if location else None,
            home_position=Position(lat=first_location.latitude, lng=first_location.longitude) if first_location else None,
            rotation=None,
            altitude=location.height_above_takeoff if location else None,
            height=location.height_above_takeoff if location else None,
            x_speed=location.speed if location else None,
            y_speed=location.vertical_speed if location else None,
            z_speed=None,
            spoofed=None
        )
    
    def get_drone_flight_start_times(self, sender_id: str, activity_offset: timedelta) -> List[datetime]:
        with Session(self.db_engine) as session:
            query = session.query(LocationMessage) \
                .filter(LocationMessage.sender_id == sender_id) \
                .order_by(LocationMessage.received_at.asc())

            flight_start_times = []
            latest_timestamp = None

            for drone in query:
                if latest_timestamp is None or drone.received_at > latest_timestamp + activity_offset:
                    latest_timestamp = drone.received_at
                    flight_start_times.append(latest_timestamp)

            return flight_start_times
    
    def get_flight_history(self, sender_id: str, flight: datetime, activity_offset: timedelta) -> List[Dict[str, Any]]:
        with Session(self.db_engine) as session:
            query = session.query(LocationMessage) \
                .filter(LocationMessage.sender_id == sender_id) \
                .filter(LocationMessage.received_at >= flight) \
                .order_by(LocationMessage.received_at.asc())

            latest_timestamp = None
            path = []

            for drone in query:
                if latest_timestamp is None:
                    latest_timestamp = drone.received_at

                if drone.received_at > latest_timestamp + activity_offset:
                    break
            
                path.append({
                    "timestamp": drone.received_at,
                    "position": {
                        "latitude": drone.latitude,
                        "longitude": drone.longitude,
                        "altitude": drone.height_above_takeoff
                    }
                })

            return path

    def exists(self, sender_id: str) -> bool:
        """
        Check if a database entry exists for the given sender_id.

        Args:
            sender_id: The sender's identifier (MAC address for WiFi)

        Returns:
            True if an entry exists, False otherwise.
        """
        with Session(self.db_engine) as session:
            # Check if any BasicIdMessage exists with the given sender_id
            exists = session.query(BasicIdMessage).filter(BasicIdMessage.sender_id == sender_id).first() is not None
        return exists
