from sqlalchemy.orm import Session
from typing import List, Dict, Any
from datetime import datetime, timedelta
from .drone_service import DroneService
from models.dtomodels import DroneDto, Position

from models.direct_remote_id import (
    DjiMessage
)

class DroneServiceDji(DroneService):
    """Service for handling drone-related operations"""
    def __init__(self, db_engine):
        self.db_engine = db_engine

    def get_all_drone_senders(self) -> List[str]:
        with Session(self.db_engine) as session:
            ids = session.query(DjiMessage.sender_id).distinct().all()
        return [id[0] for id in ids]

    def get_active_drone_senders(self) -> List[str]:
        time_threshold = datetime.now() - self._active_drone_max_age
        with Session(self.db_engine) as session:
            ids = session.query(DjiMessage.sender_id).filter(DjiMessage.received_at > time_threshold).distinct().all()
        return [id[0] for id in ids]

    def get_drone_state(self, sender_id: str) -> DroneDto:
        with Session(self.db_engine) as session:
            dji_message = session.query(DjiMessage).filter(DjiMessage.sender_id == sender_id).order_by(DjiMessage.received_at.desc()).first()

        if not dji_message:
            return None

        return DroneDto(
            serial_number=dji_message.serial_number,
            position=Position(lat=dji_message.dji_latitude, lng=dji_message.dji_longitude),
            pilot_position=Position(lat=dji_message.dji_pilot_latitude, lng=dji_message.dji_pilot_longitude) if dji_message.dji_pilot_latitude and dji_message.dji_pilot_longitude else None,
            home_position=None,  # No direct mapping available
            rotation=dji_message.dji_yaw,
            altitude=dji_message.dji_height,
            height=dji_message.dji_height,  # Assuming height is the same as altitude
            x_speed=dji_message.dji_x_speed,
            y_speed=dji_message.dji_y_speed,
            z_speed=None  # No direct mapping available
        )

    def get_drone_flight_start_times(self, sender_id: str, activity_offset: timedelta) -> List[datetime]:
        with Session(self.db_engine) as session:
            query = session.query(DjiMessage) \
                .filter(DjiMessage.sender_id == sender_id) \
                .order_by(DjiMessage.received_at.asc())

            flight_start_times = []
            latest_timestamp = None

            for drone in query:
                if latest_timestamp is None or drone.received_at > latest_timestamp + activity_offset:
                    latest_timestamp = drone.received_at
                    flight_start_times.append(latest_timestamp)

            return flight_start_times

    def get_flight_history(self, sender_id: str, flight: datetime, activity_offset: timedelta) -> List[Dict[str, Any]]:
        with Session(self.db_engine) as session:
            query = session.query(DjiMessage) \
                .filter(DjiMessage.sender_id == sender_id) \
                .filter(DjiMessage.received_at >= flight) \
                .order_by(DjiMessage.received_at.asc())

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
                        "latitude": drone.dji_latitude,
                        "longitude": drone.dji_longitude,
                        "altitude": drone.dji_height
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
            exists = session.query(DjiMessage).filter(DjiMessage.sender_id == sender_id).first() is not None
        return exists
    

