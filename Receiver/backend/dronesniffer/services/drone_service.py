import abc
from typing import List, Dict, Any
from datetime import timedelta, datetime
from models.dtomodels import DroneDto 


class DroneService(abc.ABC):
    """
    Abstract base class for drone services.
    """
    
    _active_drone_max_age: timedelta = timedelta(minutes=1) # Maximum age of a drone to be considered active
    
    @abc.abstractmethod
    def get_all_drone_senders(self) -> List[str]:
        """
        Get all drone senders
        
        Returns:
            List of sender IDs
        """
        pass

    @abc.abstractmethod
    def get_active_drone_senders(self) -> List[str]:
        """
        Get all active drone senders
        
        Returns:
            List of active sender IDs
        """
        pass
        
    @abc.abstractmethod
    def get_drone_state(self, sender_id: str) -> DroneDto:
        """
        Get the latest state for a specific drone
        
        Args:
            sender_id: The sender's identifier (MAC address for WiFi)
            
        Returns:
            DroneState containing the latest state of the drone
        """
        pass

    @abc.abstractmethod
    def get_drone_flight_start_times(self, sender_id: str, activity_offset: timedelta) -> List[datetime]:
        """
        Get the start times of all flights for a specific drone
        
        Args:
            sender_id: The sender's identifier (MAC address for WiFi)
            activity_offset: Time offset to consider for flight start
        
        Returns:
            List of flight start times
        """
        pass
        
    @abc.abstractmethod
    def get_flight_history(self, sender_id: str, flight: datetime, activity_offset: timedelta) -> List[Dict[str, Any]]:
        """
        Get the history of a specific flight for a drone
        
        Args:
            sender_id: The sender's identifier (MAC address for WiFi)
            flight: Start time of the flight
            activity_offset: Time offset to consider for flight history
        
        Returns:
            List of dictionaries containing flight history data
        """
        pass

    @abc.abstractmethod
    def exists(self, sender_id: str) -> bool:
        """
        Check if a database entry exists for the given sender_id.

        Args:
            sender_id: The sender's identifier (MAC address for WiFi)

        Returns:
            True if an entry exists, False otherwise.
        """
        pass
    
    