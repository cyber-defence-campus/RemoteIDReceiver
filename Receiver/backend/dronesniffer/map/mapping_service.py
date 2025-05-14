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
        if parsed_message.is_dji:
            db_models.append(RemoteIdMapper._map_dji_message(parsed_message, sender_id))
        elif parsed_message.is_ads_stan and parsed_message.message.message_type == 0xF: # ADS-STAN message groups, grouped in a single message
            for message in parsed_message.message.messages:
                db_model = RemoteIdMapper._map_ads_stan_message(ParsedMessage(provider="ADS-STAN", message=message), sender_id)
                if db_model:
                    db_models.append(db_model)
        elif parsed_message.is_ads_stan: # Individual ADS-STAN messages, not grouped
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
        if parsed_message.is_dji:
            return RemoteIdMapper._map_dji_message(parsed_message, sender_id)
        elif parsed_message.is_ads_stan:
            return RemoteIdMapper._map_ads_stan_message(parsed_message, sender_id)
        else:
            LOG.warning(f"Failed to map message: {parsed_message.message}")
        return None

    @staticmethod
    def _map_dji_message(parsed_message: ParsedMessage, sender_id: str) -> DjiMessage:
        """Map a DJI ParsedMessage to a DjiMessage database model."""
        message = parsed_message.message
        return DjiMessage(
            message_type=0xA,  
            version=message.version if hasattr(message, 'version') else 0x0,
            sender_id=sender_id,
            received_at=datetime.now(timezone.utc),
            serial_number=message.serial_number,
            dji_longitude=message.lng,
            dji_latitude=message.lat,
            dji_height=message.height,
            dji_x_speed=message.x_speed,
            dji_y_speed=message.y_speed,
            dji_yaw=message.yaw,
            dji_pilot_latitude=message.pilot_lat,
            dji_pilot_longitude=message.pilot_lng
        )

    @staticmethod
    def _map_ads_stan_message(parsed_message: ParsedMessage, sender_id: str) -> Optional[BasicIdMessage | LocationMessage | SelfIdMessage | SystemMessage | OperatorMessage]:
        """Map an ADS-STAN ParsedMessage to the appropriate database model."""
        message = parsed_message.message
        
        # Common fields for all message types
        base_fields = {
            'version': message.version,
            'sender_id': sender_id,
            'received_at': datetime.now(timezone.utc),
            'message_type': message.message_type
        }
        
        # Map based on message type
        if message.message_type == 0x0:  # Basic ID
            return BasicIdMessage(
                **base_fields,
                id_type=message.id_type,
                ua_type=message.ua_type,
                uas_id=message.uas_id
            )
        elif message.message_type == 0x1:  # Location
            return LocationMessage(
                **base_fields,
                operational_status=message.operational_status,
                is_reserved=message.is_reserved,
                height_type=message.height_type,
                track_direction=message.track_direction,
                speed=message.speed,
                vertical_speed=message.vertical_speed,
                latitude=message.latitude,
                longitude=message.longitude,
                altitude_barometric=message.altitude_barometric,
                altitude_geodetic=message.altitude_geodetic,
                height_above_takeoff=message.height_above_takeoff,
                accuracy_horizontal=message.accuracy_horizontal,
                accuracy_vertical=message.accuracy_vertical,
                accuracy_speed=message.accuracy_speed,
                accuracy_barometric_altitude=message.accuracy_barometric_altitude,
                accuracy_timestamp=message.accuracy_timestamp
            )
        elif message.message_type == 0x3:  # Self ID
            return SelfIdMessage(
                **base_fields,
                description_type=message.description_type,
                description=message.description
            )
        elif message.message_type == 0x4:  # System
            return SystemMessage(
                **base_fields,
                classification_type=message.classification_type,
                location_source=message.location_source,
                pilot_latitude=message.pilot_latitude,
                pilot_longitude=message.pilot_longitude,
                area_count=message.area_count,
                area_radius=message.area_radius,
                area_ceiling=message.area_ceiling,
                area_floor=message.area_floor,
                ua_category=message.ua_category,
                ua_class=message.ua_class,
                pilot_geodetic_altitude=message.pilot_geodetic_altitude
            )
        elif message.message_type == 0x5:  # Operator ID
            return OperatorMessage(
                **base_fields,
                operator_id_type=message.operator_id_type,
                operator_id=message.operator_id
            )
        return None

# Create a singleton instance for easy access
mapper = RemoteIdMapper()