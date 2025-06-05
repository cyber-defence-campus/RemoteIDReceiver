from typing import List, Optional
from datetime import datetime, timezone
import logging

from parse.parser_service import ParsedMessage
from models.direct_remote_id import (
    BasicIdMessage,
    LocationMessage,
    SelfIdMessage,
    SystemMessage,
    OperatorMessage,
    DjiMessage
)

LOG = logging.getLogger(__name__)

class RemoteIdMapper:
    """Service for mapping ParsedMessage objects to database models."""
   
    @staticmethod
    def to_db_models(parsed_message: ParsedMessage, sender_id="test-sender") -> List[BasicIdMessage | LocationMessage | SelfIdMessage | SystemMessage | OperatorMessage | DjiMessage] | None:
        """
        Convert a ParsedMessage to the appropriate database model.
        
        Args:
            parsed_message: The parsed message to convert
            
        Returns:
            A list of the appropriate database model instances or None if conversion fails
        """
        db_models = []
        if parsed_message.provider == "DJI":
            db_models.append(RemoteIdMapper._map_dji_message(parsed_message, sender_id))
        elif parsed_message.provider == "ADS-STAN" and parsed_message.message_type == 0xF: # ADS-STAN message groups, grouped in a single message
            for message in parsed_message.messages:
                db_model = RemoteIdMapper._map_ads_stan_message(message, sender_id)
                if db_model:
                    db_models.append(db_model)
        elif parsed_message.provider == "ADS-STAN": # Individual ADS-STAN messages, not grouped
            db_model = RemoteIdMapper._map_ads_stan_message(parsed_message, sender_id)
            if db_model:
                db_models.append(db_model)
        else:
            LOG.warning(f"Unknown message type for message: {parsed_message}")
            
        return db_models 

    @staticmethod
    def to_db_model(parsed_message: ParsedMessage, sender_id="test-sender") -> Optional[BasicIdMessage | LocationMessage | SelfIdMessage | SystemMessage | OperatorMessage | DjiMessage]:
        """
        Convert a ParsedMessage to the appropriate database model.
        
        Args:
            parsed_message: The parsed message to convert
            
        Returns:
            The appropriate database model instance or None if conversion fails
        """
        if parsed_message.provider == "DJI":
            return RemoteIdMapper._map_dji_message(parsed_message, sender_id)
        elif parsed_message.provider == "ADS-STAN":
            return RemoteIdMapper._map_ads_stan_message(parsed_message, sender_id)
        else:
            LOG.warning(f"Failed to map message: {parsed_message}")
        return None

    @staticmethod
    def _map_dji_message(parsed_message: ParsedMessage, sender_id: str) -> DjiMessage:
        """Map a DJI ParsedMessage to a DjiMessage database model."""
        return DjiMessage(
            message_type=0xA,  
            version=parsed_message.version if hasattr(parsed_message, 'version') else 0x0,
            sender_id=sender_id,
            received_at=datetime.now(timezone.utc),
            serial_number=parsed_message.serial_number,
            dji_longitude=parsed_message.lng,
            dji_latitude=parsed_message.lat,
            dji_height=parsed_message.height,
            dji_x_speed=parsed_message.x_speed,
            dji_y_speed=parsed_message.y_speed,
            dji_yaw=parsed_message.yaw,
            dji_pilot_latitude=parsed_message.pilot_lat,
            dji_pilot_longitude=parsed_message.pilot_lng
        )

    @staticmethod
    def _map_ads_stan_message(parsed_message: ParsedMessage, sender_id: str) -> Optional[BasicIdMessage | LocationMessage | SelfIdMessage | SystemMessage | OperatorMessage]:
        """Map an ADS-STAN ParsedMessage to the appropriate database model."""
        
        # Common fields for all message types
        base_fields = {
            'version': parsed_message.version,
            'sender_id': sender_id,
            'received_at': datetime.now(timezone.utc),
            'message_type': parsed_message.message_type
        }
        
        # Map based on message type
        if parsed_message.message_type == 0x0:  # Basic ID
            return BasicIdMessage(
                **base_fields,
                id_type=parsed_message.id_type,
                ua_type=parsed_message.ua_type,
                uas_id=parsed_message.uas_id
            )
        elif parsed_message.message_type == 0x1:  # Location
            return LocationMessage(
                **base_fields,
                operational_status=parsed_message.operational_status,
                is_reserved=parsed_message.is_reserved,
                height_type=parsed_message.height_type,
                track_direction=parsed_message.track_direction,
                speed=parsed_message.speed,
                vertical_speed=parsed_message.vertical_speed,
                latitude=parsed_message.latitude,
                longitude=parsed_message.longitude,
                altitude_barometric=parsed_message.altitude_barometric,
                altitude_geodetic=parsed_message.altitude_geodetic,
                height_above_takeoff=parsed_message.height_above_takeoff,
                accuracy_horizontal=parsed_message.accuracy_horizontal,
                accuracy_vertical=parsed_message.accuracy_vertical,
                accuracy_speed=parsed_message.accuracy_speed,
                accuracy_barometric_altitude=parsed_message.accuracy_barometric_altitude,
                accuracy_timestamp=parsed_message.accuracy_timestamp
            )
        elif parsed_message.message_type == 0x3:  # Self ID
            return SelfIdMessage(
                **base_fields,
                description_type=parsed_message.description_type,
                description=parsed_message.description
            )
        elif parsed_message.message_type == 0x4:  # System
            return SystemMessage(
                **base_fields,
                classification_type=parsed_message.classification_type,
                location_source=parsed_message.location_source,
                pilot_latitude=parsed_message.pilot_latitude,
                pilot_longitude=parsed_message.pilot_longitude,
                area_count=parsed_message.area_count,
                area_radius=parsed_message.area_radius,
                area_ceiling=parsed_message.area_ceiling,
                area_floor=parsed_message.area_floor,
                ua_category=parsed_message.ua_category,
                ua_class=parsed_message.ua_class,
                pilot_geodetic_altitude=parsed_message.pilot_geodetic_altitude
            )
        elif parsed_message.message_type == 0x5:  # Operator ID
            return OperatorMessage(
                **base_fields,
                operator_id_type=parsed_message.operator_id_type,
                operator_id=parsed_message.operator_id
            )
        return None

# Create a singleton instance for easy access
mapper = RemoteIdMapper()