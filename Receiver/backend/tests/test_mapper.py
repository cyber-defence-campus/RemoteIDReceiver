import pytest
from datetime import datetime, timezone
from unittest.mock import Mock
from parse.ads_stan.messages.basic_id import BasicIdMessage as AdsBasicIdMessage
from parse.ads_stan.messages.location_vector import LocationVectorMessage as AdsLocationMessage
from parse.ads_stan.messages.self_id import SelfIdMessage as AdsSelfIdMessage
from parse.ads_stan.messages.system_message import SystemMessage as AdsSystemMessage
from parse.ads_stan.messages.operator_id import OperatorIdMessage as AdsOperatorMessage
from parse.ads_stan.messages.message_pack import MessagePack
from parse.dji.messages.dji_message import DjiMessage as ParsedDjiMessage
from parse.parser_service import ParsedMessage
from map.mapping_service import RemoteIdMapper
from models.direct_remote_id import (
    BasicIdMessage,
    LocationMessage,
    SelfIdMessage,
    SystemMessage,
    OperatorMessage,
    DjiMessage
)

class TestRemoteIdMapper:
    """Test suite for RemoteIdMapper class."""

    def test_map_dji_message(self):
        """Test mapping of DJI message to DjiMessage model."""
        # Create DJI message
        message_type = 0xA
        serial_number = "DJI123456"
        longitude = 8.123456
        latitude = 47.123456
        height = 100.5
        x_speed = 10.0
        y_speed = 5.0
        yaw = 45.0
        pilot_latitude = 47.123457
        pilot_longitude = 8.123457

        mock_dji_message = ParsedDjiMessage(
            serial_number=serial_number,
            lng=longitude,
            lat=latitude,
            height=height,
            x_speed=x_speed,
            y_speed=y_speed,
            yaw=yaw,
            home_lng=longitude,
            home_lat=latitude,
            uuid="DJI123456",
            timestamp=datetime.now(timezone.utc),
            oui="DJI",
            pilot_lat=pilot_latitude,
            pilot_lng=pilot_longitude
        )
        parsed_message: DjiMessage = ParsedMessage(provider="DJI", message=mock_dji_message)
        
        # Map to database model
        result = RemoteIdMapper.to_db_model(parsed_message, "00:11:22:33:44:55")

        # Verify result
        assert isinstance(result, DjiMessage)
        assert result.message_type == message_type
        assert result.sender_id == "00:11:22:33:44:55"
        assert result.serial_number == serial_number
        assert result.dji_longitude == pytest.approx(longitude)
        assert result.dji_latitude == pytest.approx(latitude)
        assert result.dji_height == pytest.approx(height)
        assert result.dji_x_speed == pytest.approx(x_speed)
        assert result.dji_y_speed == pytest.approx(y_speed)
        assert result.dji_yaw == pytest.approx(yaw)
        assert result.dji_pilot_latitude == pytest.approx(pilot_latitude)
        assert result.dji_pilot_longitude == pytest.approx(pilot_longitude)


    def test_map_basic_id_message(self):
        """Test mapping of Basic ID message to BasicIdMessage model."""
        # Create Basic ID message
        basic_id = AdsBasicIdMessage(
            id_type=1,
            ua_type=2,
            uas_id="UAS123456"
        )

        parsed_message = ParsedMessage(provider="ADS-STAN", message=basic_id)
        
        # Map to database model
        result = RemoteIdMapper.to_db_model(parsed_message)
        
        # Verify result
        assert isinstance(result, BasicIdMessage)
        assert result.message_type == 0x0
        assert result.version == 0x0
        assert result.id_type == 1
        assert result.ua_type == 2
        assert result.uas_id == "UAS123456"

    def test_map_location_message(self):
        """Test mapping of Location message to LocationMessage model."""
        # Create Location message
        location = AdsLocationMessage(
            operational_status=1,
            is_reserved=False,
            height_type=1,
            track_direction=45,
            speed=10,
            vertical_speed=2,
            latitude=47.123456,
            longitude=8.123456,
            altitude_barometric=100,
            altitude_geodetic=100,
            height_above_takeoff=50,
            timestamp=0,
            accuracy_horizontal=1,
            accuracy_vertical=1,
            accuracy_speed=1,
            accuracy_barometric_altitude=1,
            accuracy_timestamp=1
        )

        parsed_message = ParsedMessage(provider="ADS-STAN", message=location)
        
        # Map to database model
        result = RemoteIdMapper.to_db_model(parsed_message)
        
        # Verify result
        assert isinstance(result, LocationMessage)
        assert result.message_type == 0x1
        assert result.version == 0x0
        assert result.operational_status == 1
        assert result.is_reserved is False
        assert result.height_type == 1
        assert result.track_direction == 45
        assert result.speed == pytest.approx(10)
        assert result.vertical_speed == pytest.approx(2)
        assert result.latitude == pytest.approx(47.123456)
        assert result.longitude == pytest.approx(8.123456)
        assert result.altitude_barometric == pytest.approx(100)
        assert result.altitude_geodetic == pytest.approx(100)
        assert result.height_above_takeoff == pytest.approx(50)
        assert result.accuracy_horizontal == pytest.approx(1)
        assert result.accuracy_vertical == pytest.approx(1)
        assert result.accuracy_speed == pytest.approx(1)
        assert result.accuracy_barometric_altitude == pytest.approx(1)
        assert result.accuracy_timestamp == pytest.approx(1)

    def test_map_self_id_message(self):
        """Test mapping of Self ID message to SelfIdMessage model."""
        # Create Self ID message
        self_id = AdsSelfIdMessage(
            description_type=1,
            description="Test Description"
        )

        parsed_message = ParsedMessage(provider="ADS-STAN", message=self_id)
        
        # Map to database model
        result = RemoteIdMapper.to_db_model(parsed_message)
        
        # Verify result
        assert isinstance(result, SelfIdMessage)
        assert result.message_type == 0x3
        assert result.version == 0x0
        assert result.description_type == 1
        assert result.description == "Test Description"

    def test_map_system_message(self):
        """Test mapping of System message to SystemMessage model."""
        # Create System message
        system = AdsSystemMessage(
            classification_type=1,
            location_source=1,
            pilot_latitude=47.123456,
            pilot_longitude=8.123456,
            area_count=1,
            area_radius=100,
            area_ceiling=100,
            area_floor=0,
            ua_category=1,
            ua_class=1,
            pilot_geodetic_altitude=100
        )

        parsed_message = ParsedMessage(provider="ADS-STAN", message=system)
        
        # Map to database model
        result = RemoteIdMapper.to_db_model(parsed_message)
        
        # Verify result
        assert isinstance(result, SystemMessage)
        assert result.message_type == 0x4
        assert result.version == 0x0
        assert result.classification_type == 1
        assert result.location_source == 1
        assert result.pilot_latitude == pytest.approx(47.123456)
        assert result.pilot_longitude == pytest.approx(8.123456)
        assert result.area_count == 1
        assert result.area_radius == pytest.approx(100)
        assert result.area_ceiling == pytest.approx(100)
        assert result.area_floor == pytest.approx(0)
        assert result.ua_category == 1
        assert result.ua_class == 1
        assert result.pilot_geodetic_altitude == pytest.approx(100)

    def test_map_operator_message(self):
        """Test mapping of Operator ID message to OperatorMessage model."""
        # Create Operator ID message
        operator = AdsOperatorMessage(
            operator_id_type=1,
            operator_id="OP123456"
        )

        parsed_message = ParsedMessage(provider="ADS-STAN", message=operator)
        
        # Map to database model
        result = RemoteIdMapper.to_db_model(parsed_message)
        
        # Verify result
        assert isinstance(result, OperatorMessage)
        assert result.message_type == 0x5
        assert result.version == 0x0
        assert result.operator_id_type == 1
        assert result.operator_id == "OP123456"

    def test_unknown_provider(self):
        """Test handling of unknown provider."""
        mock_message = Mock()
        parsed_message = ParsedMessage(provider="UNKNOWN", message=mock_message)
        
        result = RemoteIdMapper.to_db_model(parsed_message)
        assert result is None

    def test_unknown_message_type(self):
        """Test handling of unknown message type for ADS-STAN."""
        mock_message = Mock()
        mock_message.message_type = 0xFF  # Unknown message type
        mock_message.version = 1
        mock_message.sender_id = "00:11:22:33:44:55"
        
        parsed_message = ParsedMessage(provider="ADS-STAN", message=mock_message)
        
        result = RemoteIdMapper.to_db_model(parsed_message)
        assert result is None

    def test_map_message_pack(self):
        """Test mapping of Message Pack (type 0xF) to multiple database models."""
        # Create individual messages
        basic_id = AdsBasicIdMessage(
            id_type=1,
            ua_type=2,
            uas_id="UAS123456"
        )

        location = AdsLocationMessage(
            operational_status=1,
            is_reserved=False,
            height_type=1,
            track_direction=45,
            speed=10,
            vertical_speed=2,
            latitude=47.123456,
            longitude=8.123456,
            altitude_barometric=100,
            altitude_geodetic=100,
            height_above_takeoff=50,
            timestamp=0,
            accuracy_horizontal=1,
            accuracy_vertical=1,
            accuracy_speed=1,
            accuracy_barometric_altitude=1,
            accuracy_timestamp=1
        )

        self_id = AdsSelfIdMessage(
            description_type=1,
            description="Test Description"
        )

        # Create message pack containing multiple messages
        message_pack = MessagePack([basic_id, location, self_id])

        parsed_message = ParsedMessage(provider="ADS-STAN", message=message_pack)
        
        # Map to database models
        results = RemoteIdMapper.to_db_models(parsed_message, "00:11:22:33:44:55")
        
        # Verify results
        assert len(results) == 3
        
        # Verify Basic ID message
        basic_id_result = next(r for r in results if isinstance(r, BasicIdMessage))
        assert basic_id_result.message_type == 0x0
        assert basic_id_result.version == 0x0
        assert basic_id_result.sender_id == "00:11:22:33:44:55"
        assert basic_id_result.id_type == 1
        assert basic_id_result.ua_type == 2
        assert basic_id_result.uas_id == "UAS123456"
        
        # Verify Location message
        location_result = next(r for r in results if isinstance(r, LocationMessage))
        assert location_result.message_type == 0x1
        assert location_result.version == 0x0
        assert location_result.sender_id == "00:11:22:33:44:55"
        assert location_result.operational_status == 1
        assert location_result.is_reserved is False
        assert location_result.height_type == 1
        assert location_result.track_direction == 45
        assert location_result.speed == pytest.approx(10)
        assert location_result.vertical_speed == pytest.approx(2)
        assert location_result.latitude == pytest.approx(47.123456)
        assert location_result.longitude == pytest.approx(8.123456)
        assert location_result.altitude_barometric == pytest.approx(100)
        assert location_result.altitude_geodetic == pytest.approx(100)
        assert location_result.height_above_takeoff == pytest.approx(50)
        assert location_result.accuracy_horizontal == pytest.approx(1)
        assert location_result.accuracy_vertical == pytest.approx(1)
        assert location_result.accuracy_speed == pytest.approx(1)
        assert location_result.accuracy_barometric_altitude == pytest.approx(1)
        assert location_result.accuracy_timestamp == pytest.approx(1)
        
        # Verify Self ID message
        self_id_result = next(r for r in results if isinstance(r, SelfIdMessage))
        assert self_id_result.message_type == 0x3
        assert self_id_result.version == 0x0
        assert self_id_result.sender_id == "00:11:22:33:44:55"
        assert self_id_result.description_type == 1
        assert self_id_result.description == "Test Description"
